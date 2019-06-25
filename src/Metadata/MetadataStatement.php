<?php


namespace MadWizard\WebAuthn\Metadata;

use MadWizard\WebAuthn\Exception\ParseException;
use MadWizard\WebAuthn\Format\DataValidator;

class MetadataStatement
{
    /** @var null|string */
    private $aaid;

    /** @var null|string */
    private $aaguid;

    /** @var null|string[] */
    private $attestationCertificateKeyIdentifiers;

    /** @var string */
    private $description;

    /** @var int */
    private $authenticatorVersion;

    /** @var null|string */
    private $protocolFamily;

    /** @var Version[] */
    private $upv;

    /** @var string */
    private $assertionScheme;

    /** @var int */
    private $authenticationAlgorithm;

    /** @var int */
    private $publicKeyAlgAndEncoding;

    /** @var int[] */
    private $attestationTypes;

    /** @var VerificationMethodDescriptor[] */
    private $userVerificationDetails;

    /** @var int */
    private $keyProtection;

    /** @var null|boolean */
    private $isKeyRestricted;

    /** @var null|boolean */
    private $isFreshUserVerificationRequired;

    /** @var int */
    private $matcherProtection;

    /** @var int */
    private $attachmentHint;         // TODO 32-bit unsigned problem?

    /** @var boolean */
    private $isSecondFactorOnly;

    /** @var int */
    private $tcDisplay;

    /** @var null|string */
    private $tcDisplayContentType;

    /** @var null|DisplayPNGCharacteristicsDescriptor[] */
    private $tcDisplayPNGCharacteristics;

    /** @var string[] */
    private $attestationRootCertificates;

    /** @var null|EcdaaTrustAnchor[] */
    private $ecdaaTrustAnchors;

    /** @var null|string */
    private $icon;

    /** @var null|ExtensionDescriptor[] */
    private $supportedExtensions;

    public static function decodeJson(string $json)
    {
        $data = \json_decode($json, true, 20);
        if ($data === null) {
            throw new ParseException('Invalid JSON metadata statement.');
        }

        DataValidator::checkTypes(
            $data,
            [
                'aaid' => '?string',   // !!!!
                'aaguid' => '?string', // !!!!
                'attestationCertificateKeyIdentifiers' => '?array',  // !!!!
                'description' => 'string',
                'authenticatorVersion' => 'integer',
                'protocolFamily' => '?string',
                'upv' => 'array', // !!!!
                'assertionScheme' => 'string',
                'authenticationAlgorithm' => 'integer',
                'publicKeyAlgAndEncoding' => 'integer',
                'attestationTypes' => 'array',  // !!!!
                'userVerificationDetails' => 'array', // !!!!
                'keyProtection' => 'integer',
                'isKeyRestricted' => '?boolean',
                'isFreshUserVerificationRequired' => '?boolean',
                'matcherProtection' => 'integer',
                'attachmentHint' => 'integer',
                'isSecondFactorOnly' => 'boolean',
                'tcDisplay' => 'integer',
                'tcDisplayContentType' => '?string',
                'tcDisplayPNGCharacteristics' => '?array',  // !!!!
                'attestationRootCertificates' => 'array', // !!!!
                'ecdaaTrustAnchors' => '?array', // !!!!
                'icon' => '?string',
                'supportedExtensions[]' => '?array', // !!!!

            ],
            false
        );
    }
}
