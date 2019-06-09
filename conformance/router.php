<?php

use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Credential\CredentialRegistration;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Credential\UserCredentialInterface;
use MadWizard\WebAuthn\Crypto\CoseKey;
use MadWizard\WebAuthn\Dom\AuthenticatorSelectionCriteria;
use MadWizard\WebAuthn\Dom\PublicKeyCredentialDescriptor;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Extension\UnknownExtensionInput;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\UserIdentity;
use MadWizard\WebAuthn\Server\WebAuthnServer;

require __DIR__ . '/../vendor/autoload.php';



class StatusException extends Exception
{
}


// TODO supply this class in lib?
class UserCred implements UserCredentialInterface
{
    /**
     * @var string
     */
    private $credentialId;

    /**
     * @var CoseKey
     */
    private $publicKey;

    /**
     * @var ByteBuffer
     */
    private $userHandle;

    public function __construct(string $credentialId, CoseKey $publicKey, ByteBuffer $userHandle)
    {
        $this->credentialId = $credentialId;
        $this->publicKey = $publicKey;
        $this->userHandle = $userHandle;
    }

    /**
     * @return string
     */
    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    /**
     * @return CoseKey
     */
    public function getPublicKey(): CoseKey
    {
        return $this->publicKey;
    }

    /**
     * @return ByteBuffer
     */
    public function getUserHandle(): ByteBuffer
    {
        return $this->userHandle;
    }
}

session_start();

$store = new class implements CredentialStoreInterface {
    public function findCredential(string $credentialId): ?UserCredentialInterface
    {
        return $_SESSION['credentials'][$credentialId] ?? null;
    }

    public function registerCredential(CredentialRegistration $credential)
    {
        // TODO: Implement registerCredential() method.

        $_SESSION['credentials'][$credential->getCredentialId()] =
            [
                new UserCred($credential->getCredentialId(), $credential->getPublicKey(), $credential->getUserHandle()),
                null
            ];
    }

    public function getSignatureCounter(string $credentialId): ?int
    {
        return $_SESSION['credentials'][$credentialId][1] ?? null;
    }

    public function updateSignatureCounter(string $credentialId, int $counter): void
    {
        $_SESSION['credentials'][$credentialId][1] = $counter;
    }

    public function getAllFor(ByteBuffer $userHandle) : array
    {
        return array_filter($_SESSION['credentials'] ?? [], function ($cred) use ($userHandle) {
            return $userHandle->equals($cred[0]->getUserHandle());
        });
    }
};

$server = new class($store) {
    /**
     * @var WebAuthnServer
     */
    private $server;

    /**
     * @var CredentialStoreInterface
     */
    private $store;

    public function __construct(CredentialStoreInterface $store)
    {
        $config = new WebAuthnConfiguration();
        $config->setRelyingPartyName('Test server');
        $config->setRelyingPartyId('localhost');
        $config->setRelyingPartyOrigin('http://' . $_SERVER['HTTP_HOST']);
        $this->server = new WebAuthnServer($config, $store);
        $this->store = $store;
    }

    private function getPostJson() : array
    {
        $raw = file_get_contents('php://input');
        error_log($raw);
        $json = json_decode($raw, true, 10);
        if ($json === null) {
            throw new StatusException('Invalid JSON posted');
        }

        return $json;
    }

    public function run(string $url)
    {
        try {
            $response = null;
            if ($url === '/attestation/options') {
                $response = $this->attestationOptions($this->getPostJson());
            } elseif ($url === '/attestation/result') {
                $response = $this->attestationResult(file_get_contents('php://input'));
            } elseif ($url === '/assertion/options') {
                $response = $this->assertionOptions($this->getPostJson());
            } elseif ($url === '/assertion/result') {
                $response = $this->assertionResult($this->getPostJson());
            }
        } catch (StatusException $e) {
            die($e);
        } catch (WebAuthnException $e) {
            $response = [400, ['status' => 'failed', 'errorMessage' => $e->getMessage() . PHP_EOL . $e->getTraceAsString()] ];
        }


        if ($response !== null) {
            http_response_code($response[0]);
            header('Content-Type: application/json');
            die(json_encode($response[1], JSON_PRETTY_PRINT));
        }
    }

    public function attestationOptions(array $req) : array
    {
        $userIdentity = new UserIdentity(
            new ByteBuffer($req['username']),
            $req['username'],
            $req['displayName']
                );

        $sel = $req['authenticatorSelection'] ?? [];
        $crit = new AuthenticatorSelectionCriteria();
        if (($v = $sel['authenticatorAttachment'] ?? null) !== null) {
            $crit->setAuthenticatorAttachment($v);
        }
        if (($v = $sel['requireResidentKey'] ?? null) !== null) {
            $crit->setRequireResidentKey($v);
        }
        if (($v = $sel['userVerification'] ?? null) !== null) {
            $crit->setUserVerification($v);
        }

        // TODO!!!!! MOVE TO library?




        $att = $req['attestation'] ?? 'none';

        $opts = new RegistrationOptions($userIdentity);

        $opts->setAttestation($att);
        $opts->setAuthenticatorSelection($crit);
        foreach ($req['extensions'] ?? [] as $identifier => $ext) {
            $opts->addExtensionInput(new UnknownExtensionInput($identifier, $ext));
        }
        $regReq = $this->server->startRegistration($opts);

        // TODO- move to lib
        foreach ($this->store->getAllFor($userIdentity->getUserHandle()) as $c) {
            /**
             * @var UserCredentialInterface $c
             */
            $regReq->getClientOptions()->addExcludeCredential(
                new PublicKeyCredentialDescriptor(
                    ByteBuffer::fromBase64Url($c->getCredentialId())
                )
            );
        }

        $_SESSION['context'] = $regReq->getContext();
        return [200, array_merge(['status' => 'ok', 'errorMessage' => ''], $regReq->getClientOptionsJson())];
    }

    public function attestationResult(string $req) : array
    {
        $context = $_SESSION['context'];
        $this->server->finishRegistration($req, $context);
        return [200, ['status' => 'ok', 'errorMessage' => '']];
    }
};


$server->run($_SERVER['REQUEST_URI']);
