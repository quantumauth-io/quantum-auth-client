package setup

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func promptYesNo(msg string) (bool, error) {
	fmt.Print(msg)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	s := strings.TrimSpace(strings.ToLower(line))
	return s == "y" || s == "yes", nil
}
