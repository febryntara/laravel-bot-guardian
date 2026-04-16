<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;

class HeaderDetector implements DetectorInterface
{
    public function detect(Request $request): int
    {
        if (! $this->isEnabled()) {
            return 0;
        }

        $config = config('botguardian.headers');
        $score = 0;

        // Check empty user-agent
        if ($config['block_empty_user_agent']) {
            $userAgent = $request->userAgent();
            if (empty($userAgent)) {
                $score += $config['empty_user_agent_score'] ?? 25;
            } elseif (! empty($config['block_known_bots'])) {
                // Check known bot patterns
                foreach ($config['known_bot_patterns'] ?? [] as $pattern) {
                    if (stripos($userAgent, $pattern) !== false) {
                        $score += $config['known_bot_score'] ?? 15;
                        break;
                    }
                }
            }
        }

        // Check missing Accept-Language
        if (! $request->hasHeader('Accept-Language')) {
            $score += $config['missing_accept_language_score'] ?? 10;
        }

        return $score;
    }

    public function isEnabled(): bool
    {
        return config('botguardian.headers.enabled', true);
    }

    public function getName(): string
    {
        return 'headers';
    }
}
