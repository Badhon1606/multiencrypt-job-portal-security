<?php
declare(strict_types=1);

require_once __DIR__ . "/../crypto/BigInt.php";
require_once __DIR__ . "/../crypto/RSA.php";
require_once __DIR__ . "/../crypto/ECC.php";

final class KeyManager
{
    // CHANGE THIS if your secure folder is different
    private const SECURE_DIR = "C:\\xampp\\secure_keys\\";
    private const REGISTRY_FILE = __DIR__ . "/key_registry.json";

    /**
     * Initialize v1 keys if registry doesn't exist.
     */
    public static function initIfNeeded(int $rsaBits = 2048): void
    {
        if (!file_exists(self::REGISTRY_FILE)) {
            self::rotate($rsaBits); // creates version 1
        }
    }

    /**
     * Create a new key version and make it active.
     * Keeps old versions for decryption.
     */
    public static function rotate(int $rsaBits = 2048): int
    {
        self::ensureSecureDir();

        $reg = self::loadRegistry();
        $nextVersion = (int)($reg['active_version'] ?? 0) + 1;

        // Generate keys
        $rsa = RSA::generate($rsaBits);
        $ecc = ECC::keygen();

        // Save private keys (outside web root)
        $rsaPriv = [
            'n' => $rsa->private()['n'],
            'd' => $rsa->private()['d'],
            'bits' => $rsaBits,
        ];
        $eccPriv = [
            'd' => BigInt::toHex($ecc['priv']),
        ];

        $rsaPrivPath = self::SECURE_DIR . "rsa_priv_v{$nextVersion}.json";
        $eccPrivPath = self::SECURE_DIR . "ecc_priv_v{$nextVersion}.json";
        self::atomicWrite($rsaPrivPath, json_encode($rsaPriv, JSON_PRETTY_PRINT));
        self::atomicWrite($eccPrivPath, json_encode($eccPriv, JSON_PRETTY_PRINT));

        // Save public keys (in registry file)
        $rsaPub = $rsa->public(); // ['n','e','bits']
        $eccPubBytes = ECC::pubToBytes($ecc['pub']);
        $eccPub = [
            'uncompressed_b64' => base64_encode($eccPubBytes),
            'curve' => 'secp256k1'
        ];

        $reg['active_version'] = $nextVersion;
        $reg['versions'][(string)$nextVersion] = [
            'created_at' => date('c'),
            'rsa_pub' => $rsaPub,
            'ecc_pub' => $eccPub,
            // store only paths for private keys
            'rsa_priv_path' => $rsaPrivPath,
            'ecc_priv_path' => $eccPrivPath,
        ];

        self::saveRegistry($reg);
        return $nextVersion;
    }

    /**
     * Get active keys (used for encryption).
     */
    public static function getActiveKeys(): array
    {
        self::initIfNeeded();

        $reg = self::loadRegistry();
        $v = (int)$reg['active_version'];
        return self::getKeysByVersion($v);
    }

    /**
     * Get keys by version (used for decryption of older rows).
     */
    public static function getKeysByVersion(int $version): array
    {
        self::initIfNeeded();

        $reg = self::loadRegistry();
        $ver = $reg['versions'][(string)$version] ?? null;
        if (!$ver) {
            throw new RuntimeException("Key version {$version} not found");
        }

        // Load private keys
        $rsaPriv = json_decode(file_get_contents($ver['rsa_priv_path']), true);
        $eccPriv = json_decode(file_get_contents($ver['ecc_priv_path']), true);

        if (!is_array($rsaPriv) || !is_array($eccPriv)) {
            throw new RuntimeException("Private key files corrupted for v{$version}");
        }

        // Build ECC public ECPoint
        $eccPubBytes = base64_decode($ver['ecc_pub']['uncompressed_b64'], true);
        $eccPubPoint = ECC::pubFromBytes($eccPubBytes);

        return [
            'version' => $version,

            'rsa_pub' => $ver['rsa_pub'],
            'rsa_priv' => [
                'n' => $rsaPriv['n'],
                'd' => $rsaPriv['d'],
                'bits' => (int)$rsaPriv['bits'],
            ],

            'ecc_pub' => $eccPubPoint,
            'ecc_priv' => BigInt::fromHex($eccPriv['d']),
        ];
    }

    // ----------------- Helpers -----------------

    private static function ensureSecureDir(): void
    {
        if (!is_dir(self::SECURE_DIR)) {
            if (!mkdir(self::SECURE_DIR, 0700, true) && !is_dir(self::SECURE_DIR)) {
                throw new RuntimeException("Cannot create secure dir: " . self::SECURE_DIR);
            }
        }
    }

    private static function loadRegistry(): array
    {
        if (!file_exists(self::REGISTRY_FILE)) {
            return ['active_version' => 0, 'versions' => []];
        }
        $data = json_decode(file_get_contents(self::REGISTRY_FILE), true);
        if (!is_array($data)) {
            return ['active_version' => 0, 'versions' => []];
        }
        if (!isset($data['versions'])) $data['versions'] = [];
        return $data;
    }

    private static function saveRegistry(array $reg): void
    {
        self::atomicWrite(self::REGISTRY_FILE, json_encode($reg, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    private static function atomicWrite(string $path, string $content): void
    {
        $tmp = $path . ".tmp";
        file_put_contents($tmp, $content, LOCK_EX);
        rename($tmp, $path);
    }
}
