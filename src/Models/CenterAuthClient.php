<?php

namespace CenterAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Hash;

/**
 * @property int $id
 * @property string $client_id
 * @property string $name
 * @property string|null $description
 * @property string $callback_url
 * @property string $secret_hash
 * @property string|null $previous_secret_hash
 * @property Carbon|null $previous_secret_expires_at
 * @property bool $is_active
 * @property Carbon|null $last_used_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class CenterAuthClient extends Model
{
    protected $table = 'center_auth_clients';

    protected $fillable = [
        'client_id',
        'name',
        'description',
        'callback_url',
        'secret_hash',
        'previous_secret_hash',
        'previous_secret_expires_at',
        'is_active',
        'last_used_at',
    ];

    protected $hidden = [
        'secret_hash',
        'previous_secret_hash',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'previous_secret_expires_at' => 'datetime',
        'last_used_at' => 'datetime',
    ];

    public static function generateSecret(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Verify a plain client secret against the current hash or an unexpired previous hash.
     */
    public function verifySecret(string $plainSecret): bool
    {
        if ($plainSecret === '') {
            return false;
        }

        if (Hash::check($plainSecret, $this->secret_hash)) {
            return true;
        }

        if (
            $this->previous_secret_hash !== null
            && $this->previous_secret_expires_at !== null
            && $this->previous_secret_expires_at->isFuture()
            && Hash::check($plainSecret, $this->previous_secret_hash)
        ) {
            return true;
        }

        return false;
    }

    /**
     * Rotate the client secret, keeping the previous secret valid during the grace window
     * (set $graceHours = 0 to invalidate the old secret immediately).
     */
    public function rotateSecret(int $graceHours = 24): string
    {
        $newPlainSecret = self::generateSecret();

        if ($graceHours > 0 && $this->secret_hash !== '') {
            $this->previous_secret_hash = $this->secret_hash;
            $this->previous_secret_expires_at = now()->addHours($graceHours);
        } else {
            $this->previous_secret_hash = null;
            $this->previous_secret_expires_at = null;
        }

        $this->secret_hash = Hash::make($newPlainSecret);
        $this->save();

        return $newPlainSecret;
    }

    public function hasActivePreviousSecret(): bool
    {
        return $this->previous_secret_hash !== null
            && $this->previous_secret_expires_at !== null
            && $this->previous_secret_expires_at->isFuture();
    }
}
