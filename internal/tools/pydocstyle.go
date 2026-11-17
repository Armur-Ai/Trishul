package internal

import (
	"github.com/Armur-Ai/Trishul/internal/logger"
	utils "github.com/Armur-Ai/Trishul/pkg"
	"regexp"
	"strings"
)

func RunPydocstyle(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "pydocstyle").Str("dir", directory).Msg("running")
	pydocstyleResults := RunPydocstyleOnRepo(directory)
	categorizedResults := CategorizePydocstyleResults(pydocstyleResults, directory)
	return utils.ConvertCategorizedResults(categorizedResults), nil
}

func RunPydocstyleOnRepo(directory string) string {
	out, _ := RunToolCommandStdout("pydocstyle", directory)
	return string(out)
}

func CategorizePydocstyleResults(pydocstyleResults string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitCategorizedResults()
	if pydocstyleResults != "" {
		re := regexp.MustCompile(`(?P<filename>.*?):(?P<line>\d+)\s(?P<level>.*):\s+D(?P<error_code>\d{3}):\s(?P<message>.*)`)

		matches := re.FindAllStringSubmatch(pydocstyleResults, -1)

		for _, match := range matches {
			if len(match) == 6 {
				result := map[string]interface{}{
					"path":       strings.Replace(match[1], directory, "", 1),
					"line":       match[2],
					"level":      match[3],
					"error_code": "D" + match[4],
					"message":    match[5],
				}
				categorizedResults[DOCKSTRING_ABSENT] = append(categorizedResults[DOCKSTRING_ABSENT], result)
			}
		}
	}

	return categorizedResults
}
