package internal

import (
	"encoding/json"
	"github.com/Armur-Ai/Trishul/internal/logger"
	"github.com/Armur-Ai/Trishul/internal/redact"
	utils "github.com/Armur-Ai/Trishul/pkg"
	"os/exec"
	"strings"
)

type Secret struct {
	Path string      `json:"path"`
	Line interface{} `json:"line"`
	Rule struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
	} `json:"rule"`
	Secret string `json:"secret"`
}

func RunTrufflehog(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "trufflehog").Str("dir", directory).Msg("running")
	trufflehogResults, err := runTrufflehogOnRepo(directory)
	if err != nil {
		logger.Warn().Str("tool", "trufflehog").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitAdvancedCategorizedResults()), err
	}
	categorizedResults := categorizeTrufflehogResults(trufflehogResults, directory)
	return utils.ConvertCategorizedResults(categorizedResults), nil
}

func runTrufflehogOnRepo(directory string) (string, error) {
	if err := setGitSafeDirectory(directory); err != nil {
		return "", err
	}
	defer func() { _ = unsetGitSafeDirectory(directory) }()

	cmd := exec.Command("trufflehog3", "--no-entropy", "--format", "JSON", directory)
	output, _ := cmd.CombinedOutput()
	return string(output), nil
}

func setGitSafeDirectory(directory string) error {
	cmd := exec.Command("git", "config", "--global", "--add", "safe.directory", directory)
	_, err := cmd.CombinedOutput()
	return err
}

func unsetGitSafeDirectory(directory string) error {
	cmd := exec.Command("git", "config", "--global", "--unset", "safe.directory", directory)
	_, err := cmd.CombinedOutput()
	return err
}

func categorizeTrufflehogResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitAdvancedCategorizedResults()

	if results != "" {
		var secrets []Secret
		err := json.Unmarshal([]byte(results), &secrets)
		if err != nil {
			logger.Error().Str("tool", "trufflehog").Err(err).Msg("failed to parse results")
			return categorizedResults
		}

		for _, secret := range secrets {
			categorizedResults[utils.SECRET_DETECTION] = append(categorizedResults[utils.SECRET_DETECTION], formatSecretIssue(secret, directory))
		}
	}

	return categorizedResults
}

func formatSecretIssue(secret Secret, directory string) map[string]interface{} {
	return map[string]interface{}{
		"path":           strings.Replace(secret.Path, directory, "", 1),
		"line":           secret.Line,
		"message":        secret.Rule.Message,
		"severity":       secret.Rule.Severity,
		"secret_preview": redact.Mask(secret.Secret),
		"fingerprint":    redact.Fingerprint(secret.Secret),
	}
}
