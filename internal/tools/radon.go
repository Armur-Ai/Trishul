package internal

import (
	"github.com/Armur-Ai/Trishul/internal/logger"
	utils "github.com/Armur-Ai/Trishul/pkg"
	"encoding/json"
	"strings"
)

func RunRadon(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "radon").Str("dir", directory).Msg("running")
	radonResults := RunRadonOnRepo(directory)
	categorizedResults := CategorizeRadonResults(radonResults, directory)
	return utils.ConvertCategorizedResults(categorizedResults), nil
}

func RunRadonOnRepo(directory string) string {
	out, err := RunToolCommandStdout("radon", "cc", "-j", directory)
	if err != nil {
		logger.Warn().Str("tool", "radon").Err(err).Str("stderr", string(out)).Msg("tool exited with error")
		return ""
	}

	return string(out)
}

func CategorizeRadonResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitCategorizedResults()

	if results != "" {
		var parsedResults map[string][]map[string]interface{}
		err := json.Unmarshal([]byte(results), &parsedResults)
		if err != nil {
			logger.Error().Str("tool", "radon").Err(err).Msg("failed to parse results")
			return categorizedResults
		}

		for filePath, issues := range parsedResults {
			relativePath := strings.Replace(filePath, directory, "", 1)
			for _, issue := range issues {
				issue["path"] = relativePath
				categorizedResults[utils.COMPLEX_FUNCTIONS] = append(categorizedResults[utils.COMPLEX_FUNCTIONS], issue)
			}
		}
	}

	return categorizedResults
}
