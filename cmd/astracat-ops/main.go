package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ANSI color codes
const (
	ColorReset  = "\033[0m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorRed    = "\033[31m"
	ColorCyan   = "\033[36m"
)

func main() {
	printHeader()

	if !checkPrerequisites() {
		os.Exit(1)
	}

	for {
		printMenu()
		choice := readInput("Select an option: ")

		switch choice {
		case "1":
			manageNodes()
		case "2":
			deploy()
		case "3":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println(ColorRed + "Invalid option, please try again." + ColorReset)
		}
	}
}

func printHeader() {
	fmt.Println(ColorCyan + "========================================")
	fmt.Println("      AstracatDNS Admin CLI (K3s)")
	fmt.Println("========================================" + ColorReset)
}

func printMenu() {
	fmt.Println("\nMenu:")
	fmt.Println("1. Manage Nodes (Select nodes for installation)")
	fmt.Println("2. Build & Deploy (Run deploy_k3s.sh)")
	fmt.Println("3. Exit")
}

func readInput(prompt string) string {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func checkPrerequisites() bool {
	required := []string{"kubectl", "docker", "k3s"}
	allOk := true
	for _, cmd := range required {
		if _, err := exec.LookPath(cmd); err != nil {
			fmt.Printf(ColorRed+"Error: %s is not installed or not in PATH.\n"+ColorReset, cmd)
			allOk = false
		}
	}
	return allOk
}

func manageNodes() {
	fmt.Println(ColorYellow + "\nFetching nodes..." + ColorReset)
	nodes, err := getNodes()
	if err != nil {
		fmt.Printf(ColorRed+"Failed to get nodes: %v\n"+ColorReset, err)
		return
	}

	if len(nodes) == 0 {
		fmt.Println("No nodes found.")
		return
	}

	// Fetch current labels
	labeledNodes, err := getLabeledNodes()
	if err != nil {
		fmt.Printf(ColorRed+"Failed to check labels: %v\n"+ColorReset, err)
		return
	}

	fmt.Println("\nAvailable Nodes:")
	for i, node := range nodes {
		status := "[ ]"
		if labeledNodes[node] {
			status = "[" + ColorGreen + "x" + ColorReset + "]"
		}
		fmt.Printf("%d. %s %s\n", i+1, status, node)
	}

	fmt.Println("\nEnter node numbers to toggle (comma separated, e.g., '1,3'), 'a' for all, or 'q' to go back.")
	input := readInput("Selection: ")

	if input == "q" {
		return
	}

	var toToggle []string
	if input == "a" {
		toToggle = nodes
	} else {
		parts := strings.Split(input, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			var idx int
			if _, err := fmt.Sscanf(p, "%d", &idx); err == nil && idx > 0 && idx <= len(nodes) {
				toToggle = append(toToggle, nodes[idx-1])
			}
		}
	}

	for _, node := range toToggle {
		isLabeled := labeledNodes[node]
		if isLabeled {
			// Remove label
			runCommand("kubectl", "label", "node", node, "astracat-dns-")
			fmt.Printf("Node %s: %sremoved%s label\n", node, ColorRed, ColorReset)
		} else {
			// Add label
			runCommand("kubectl", "label", "node", node, "astracat-dns=true", "--overwrite")
			fmt.Printf("Node %s: %sadded%s label\n", node, ColorGreen, ColorReset)
		}
	}
}

func getNodes() ([]string, error) {
	out, err := exec.Command("kubectl", "get", "nodes", "-o", "jsonpath={.items[*].metadata.name}").Output()
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

func getLabeledNodes() (map[string]bool, error) {
	out, err := exec.Command("kubectl", "get", "nodes", "-l", "astracat-dns=true", "-o", "jsonpath={.items[*].metadata.name}").Output()
	if err != nil {
		// If no nodes match, kubectl might return empty output or error depending on version/flags?
		// usually empty output.
		return map[string]bool{}, nil
	}
	labeled := make(map[string]bool)
	for _, name := range strings.Fields(string(out)) {
		labeled[name] = true
	}
	return labeled, nil
}

func deploy() {
	fmt.Println(ColorYellow + "\nStarting deployment process..." + ColorReset)

	// Check if deploy_k3s.sh exists
	if _, err := os.Stat("deploy_k3s.sh"); os.IsNotExist(err) {
		fmt.Println(ColorRed + "deploy_k3s.sh not found!" + ColorReset)
		return
	}

	cmd := exec.Command("./deploy_k3s.sh")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf(ColorRed+"Deployment failed: %v\n"+ColorReset, err)
	} else {
		fmt.Println(ColorGreen + "\nDeployment script finished successfully." + ColorReset)
	}
}

func runCommand(name string, args ...string) {
	cmd := exec.Command(name, args...)
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error running %s: %v\n", name, err)
	}
}
