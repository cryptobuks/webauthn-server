<?php

use MadWizard\WebAuthn\Config\WebAuthnConfiguration;
use MadWizard\WebAuthn\Credential\CredentialRegistration;
use MadWizard\WebAuthn\Credential\CredentialStoreInterface;
use MadWizard\WebAuthn\Credential\UserCredentialInterface;
use MadWizard\WebAuthn\Crypto\CoseKey;
use MadWizard\WebAuthn\Dom\AuthenticatorSelectionCriteria;
use MadWizard\WebAuthn\Exception\WebAuthnException;
use MadWizard\WebAuthn\Format\ByteBuffer;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\UserIdentity;
use MadWizard\WebAuthn\Server\WebAuthnServer;

require __DIR__ . '/../vendor/autoload.php';

session_start();

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
$store = new class implements CredentialStoreInterface {
    public function findCredential(string $credentialId): ?UserCredentialInterface
    {
        // TODO: Implement findCredential() method.
    }

    public function registerCredential(CredentialRegistration $credential)
    {
        // TODO: Implement registerCredential() method.
    }

    public function getSignatureCounter(string $credentialId): ?int
    {
        // TODO: Implement getSignatureCounter() method.
    }

    public function updateSignatureCounter(string $credentialId, int $counter): void
    {
        // TODO: Implement updateSignatureCounter() method.
    }
};

$server = new class($store) {
    /**
     * @var WebAuthnServer
     */
    private $server;

    public function __construct(CredentialStoreInterface $store)
    {
        $config = new WebAuthnConfiguration();
        $config->setRelyingPartyName('Test server');
        $config->setRelyingPartyId('localhost');
        $config->setRelyingPartyOrigin('http://' . $_SERVER['HTTP_HOST']);
        $this->server = new WebAuthnServer($config, $store);
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
                $response = $this->attestationResult($this->getPostJson());
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

        $att = $req['attestation'] ?? 'none';

        $opts = new RegistrationOptions($userIdentity);
        $opts->setAttestation($att);
        $opts->setAuthenticatorSelection($crit);

        $regReq = $this->server->startRegistration($opts);
        return [200, array_merge(['status' => 'ok', 'errorMessage' => ''], $regReq->getClientOptionsJson())];
    }

    public function attestationResult(array $req) : array
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

        $att = $req['attestation'] ?? 'none';

        $opts = new RegistrationOptions($userIdentity);
        $opts->setAttestation($att);
        $opts->setAuthenticatorSelection($crit);

        $regReq = $this->server->startRegistration($opts);
        return [200, array_merge(['status' => 'ok', 'errorMessage' => ''], $regReq->getClientOptionsJson())];
    }
};


$server->run($_SERVER['REQUEST_URI']);
