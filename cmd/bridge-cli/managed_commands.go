package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"remote-bridge/internal/managedsession"
	"remote-bridge/internal/model"
)

func runSession(args []string) int {
	if len(args) == 0 {
		return fail(model.ExitUsage, errors.New("session 需要 list / status / exec / close / handoff 子命令"))
	}
	action := args[0]
	fs := flag.NewFlagSet("bridge-cli session "+action, flag.ContinueOnError)
	id, command := "", ""
	timeout := 30
	jsonOutput := false
	fs.StringVar(&id, "id", "", "托管会话编号")
	fs.StringVar(&command, "command", "", "远程 Shell 命令；按会话使用 PowerShell 或 POSIX sh")
	fs.IntVar(&timeout, "timeout", 30, "命令超时秒数，1–120")
	fs.BoolVar(&jsonOutput, "json", false, "输出 JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return int(model.ExitUsage)
	}
	if fs.NArg() != 0 {
		return fail(model.ExitUsage, errors.New("存在未识别的位置参数"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
	defer cancel()
	if action == "list" {
		items, err := sessionList(ctx)
		if err != nil {
			return fail(model.ExitConnection, err)
		}
		return printJSON(items)
	}
	if !managedsession.IDPattern.MatchString(id) {
		return fail(model.ExitUsage, errors.New("需要有效的 --id rb-... 会话编号"))
	}
	if action == "handoff" {
		response, err := sessionCall(ctx, id, managedsession.Request{Operation: "status"})
		if err != nil {
			return fail(model.ExitConnection, err)
		}
		if response.Info.State != "connected" {
			return fail(model.ExitConnection, managedsession.ErrClosed)
		}
		fmt.Println(managedsession.Handoff(response.Info, mustExecutable()))
		return 0
	}
	operation := action
	if operation != "exec" && operation != "status" && operation != "close" {
		return fail(model.ExitUsage, errors.New("不支持的 session 子命令"))
	}
	if operation == "exec" && (command == "" || timeout < 1 || timeout > 120) {
		return fail(model.ExitUsage, errors.New("exec 需要 --command，timeout 为 1–120 秒"))
	}
	response, err := sessionCall(ctx, id, managedsession.Request{Operation: operation, Command: command, Timeout: timeout})
	if err != nil {
		return fail(model.ExitConnection, err)
	}
	if jsonOutput || response.Result == nil {
		if code := printJSON(response); code != 0 {
			return code
		}
		if response.Result != nil && response.Result.ExitCode != 0 {
			return int(model.ExitRemoteCommand)
		}
		return 0
	}
	fmt.Print(response.Result.Stdout)
	if response.Result.Stderr != "" {
		fmt.Fprint(os.Stderr, response.Result.Stderr)
	}
	if response.Result.Truncated {
		fmt.Fprintln(os.Stderr, "\n输出过长，已截断。请缩小查询范围。")
	}
	if response.Result.ExitCode != 0 {
		return int(model.ExitRemoteCommand)
	}
	return 0
}
func sessionList(ctx context.Context) ([]managedsession.Info, error) {
	root, err := managedsession.DefaultRoot()
	if err != nil {
		return nil, err
	}
	return managedsession.List(ctx, root)
}
func sessionCall(ctx context.Context, id string, request managedsession.Request) (managedsession.Response, error) {
	root, err := managedsession.DefaultRoot()
	if err != nil {
		return managedsession.Response{}, err
	}
	record, err := managedsession.LoadRecord(root, id)
	if err != nil {
		return managedsession.Response{}, err
	}
	return managedsession.Call(ctx, record, request)
}
func encodeJSON(value any) string { data, _ := json.Marshal(value); return string(data) }
