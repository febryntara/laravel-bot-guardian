<?php

namespace Febryntara\LaravelBotGuardian\Detectors;

use Illuminate\Http\Request;

interface DetectorInterface
{
    /**
     * Evaluate the request and return a violation score.
     * Return 0 if no violation detected.
     */
    public function detect(Request $request): int;

    /**
     * Whether this detector is enabled in config.
     */
    public function isEnabled(): bool;

    /**
     * Description of what this detector checks (for logging).
     */
    public function getName(): string;
}
