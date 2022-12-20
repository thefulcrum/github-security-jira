<?php

declare(strict_types=1);

namespace GitHubSecurityJira;

use Reload\JiraSecurityIssue;
use JiraRestApi\Issue\IssueField;

class SecurityAlertIssue extends JiraSecurityIssue
{
    /**
     * @var string
     */
    protected string $package;

    /**
     * @var string|null
     */
    protected ?string $safeVersion;

    /**
     * @var string
     */
    protected string $vulnerableVersionRange;

    /**
     * @var string
     */
    protected string $manifestPath;

    /**
     * @var string
     */
    protected string $id;

    /**
     * @var string
     */
    protected string $severity;

    /**
     * phpcs:disable SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint.DisallowedMixedTypeHint
     *
     * @param array<string,mixed> $data
     */
    public function __construct(array $data)
    {
        // phpcs:enable SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint.DisallowedMixedTypeHint
        $this->package = $data['securityVulnerability']['package']['name'];
        $this->safeVersion = $data['securityVulnerability']['firstPatchedVersion']['identifier'] ?? null;
        $this->vulnerableVersionRange = $data['securityVulnerability']['vulnerableVersionRange'];
        $this->manifestPath = \pathinfo($data['vulnerableManifestPath'], \PATHINFO_DIRNAME);
        $this->id = $data['securityVulnerability']['advisory']['ghsaId'];
        $this->severity = $data['securityVulnerability']['severity'];

        $references = [];

        foreach ($data['securityVulnerability']['advisory']['references'] as $ref) {
            if (!\array_key_exists('url', $ref) || !\is_string($ref['url'])) {
                continue;
            }

            $references[] = $ref['url'];
        }

        $advisory_description = \wordwrap($data['securityVulnerability']['advisory']['description'] ?? '', 100);
        $ecosystem = $data['securityVulnerability']['package']['ecosystem'] ?? '';
        $githubRepo = \getenv('GITHUB_REPOSITORY') ?: '';
        $safeVersion = $this->safeVersion ?? 'no fix';

        $body = <<<EOT
- Repository: [{$githubRepo}|https://github.com/{$githubRepo}]
- Package: {$this->package} ($ecosystem)
- Vulnerable version: {$this->vulnerableVersionRange}
- Secure version: {$safeVersion}

EOT;

        if (\is_array($references) && (\count($references) > 0)) {
                $body .= "- Links: \n-- " . \implode("\n-- ", $references);
        }

        $body .= <<<EOT


{noformat}
{$advisory_description}
{noformat}
EOT;

        parent::__construct();

        $this->setKeyLabel($githubRepo);
        $this->setKeyLabel($this->uniqueId());
        $this->setTitle("{$this->package} ({$safeVersion}) - {$this->severity}");
        $this->setBody($body);

        $labels = \getenv('JIRA_ISSUE_LABELS');

        if (!$labels) {
            return;
        }

        foreach (\explode(',', $labels) as $label) {
            $this->setKeyLabel($label);
        }
    }

    /**
     * The unique ID of the severity.
     *
     * @return string
     */
    public function uniqueId(): string
    {
        // If there is no safe version we use the GHSA ID as
        // identifier. If the security alert is later updated with a
        // known safe version a side effect of this is that a new Jira
        // issue will be created. We'll consider this a positive side
        // effect.
        $identifier = $this->safeVersion ?? $this->id;

        if ($this->manifestPath === '.') {
            return "{$this->package}:{$identifier}";
        }

        return "{$this->package}:{$this->manifestPath}:{$identifier}";
    }

    /**
     * Ensure that the issue exists.
     *
     * @return string the issue id.
     */
    public function ensure(): string
    {
        $existing = $this->exists();

        if ($existing) {
            return $existing;
        }

        $issueField = new IssueField();
        $issueField->setProjectKey($this->project)
            ->setSummary($this->title)
            ->setIssueType($this->issueType)
            ->setDescription($this->body);

        foreach ($this->keyLabels as $label) {
            $issueField->addLabel($label);
        }
        
        // Set story points
        $issueField->addCustomField("customfield_10121", 0);

        // Set epic link
        $issueField->addCustomField("customfield_10005", "HUB-988");

        try {
            /** @var \JiraRestApi\Issue\Issue $ret */
            $ret = $this->issueService->create($issueField);
        } catch (Throwable $t) {
            throw new RuntimeException("Could not create issue: {$t->getMessage()}");
        }

        $addedWatchers = [];
        $notFoundWatchers = [];

        foreach ($this->watchers as $watcher) {
            $account = $this->findUser($watcher);

            if (!$account) {
                $notFoundWatchers[] = $watcher;

                continue;
            }

            $this->issueService->addWatcher($ret->key, $account->accountId);
            $addedWatchers[] = $account;
        }

        $commentText = $addedWatchers ?
            \sprintf(self::WATCHERS_TEXT, $this->formatUsers($addedWatchers)) :
            self::NO_WATCHERS_TEXT;

        if ($notFoundWatchers) {
            $commentText .= "\n\n" . \sprintf(self::NOT_FOUND_WATCHERS_TEXT, $this->formatQuoted($notFoundWatchers));
        }

        $comment = $this->createComment($commentText);

        $this->issueService->addComment($ret->key, $comment);

        return $ret->key;
    }
}
