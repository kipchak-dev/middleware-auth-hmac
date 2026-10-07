<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Config;

use Kipchak\Middleware\Auth\HMAC\Exceptions\InvalidConfiguration;

/**
 * The whole kipchak.auth.hmac config file, validated.
 */
final readonly class Settings
{
    /**
     * @param list<string> $ignorePaths
     * @param array<string, Profile> $profiles
     */
    public function __construct(
        public bool $enabled,
        public bool $ignoreOptions,
        public array $ignorePaths,
        public ?string $defaultProfile,
        public array $profiles,
        public ReplaySettings $replay,
    ) {
    }

    public static function fromArray(array $config): self
    {
        $profiles = [];
        foreach ($config['profiles'] ?? [] as $name => $profileConfig) {
            if (!is_string($name) || $name === '' || !is_array($profileConfig)) {
                throw InvalidConfiguration::at('profiles', 'must map profile names to arrays');
            }
            $profiles[$name] = Profile::fromArray($name, $profileConfig);
        }
        if ($profiles === []) {
            throw InvalidConfiguration::at('profiles', 'must define at least one profile');
        }

        $defaultProfile = $config['default_profile'] ?? null;
        if ($defaultProfile !== null && !isset($profiles[$defaultProfile])) {
            throw InvalidConfiguration::at('default_profile', "names '{$defaultProfile}', which is not a defined profile");
        }

        $ignorePaths = $config['ignore_paths'] ?? [];
        if (!is_array($ignorePaths)) {
            throw InvalidConfiguration::at('ignore_paths', 'must be a list of paths');
        }

        return new self(
            enabled: (bool) ($config['enabled'] ?? false),
            ignoreOptions: (bool) ($config['ignore_options'] ?? true),
            ignorePaths: array_values($ignorePaths),
            defaultProfile: $defaultProfile,
            profiles: $profiles,
            replay: ReplaySettings::fromArray($config['replay'] ?? []),
        );
    }

    public function profile(string $name): Profile
    {
        return $this->profiles[$name]
            ?? throw InvalidConfiguration::at('profiles', "has no profile named '{$name}'");
    }

    /**
     * The first profile whose paths cover the request path, else the default profile, else null (not protected).
     */
    public function profileForPath(string $path): ?Profile
    {
        foreach ($this->profiles as $profile) {
            if ($profile->matchesPath($path)) {
                return $profile;
            }
        }

        return $this->defaultProfile === null ? null : $this->profiles[$this->defaultProfile];
    }

    public function replayEnabledFor(Profile $profile): bool
    {
        return $this->replay->enabled && $profile->replay;
    }
}
