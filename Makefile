agent-sandbox: agent_sandbox.nim
	nim compile -d:release --opt:size -d:strip --mm:arc --hints:off --nimcache:./nim-cache -o:"$@" "$<"
.PHONY: clean
clean:
	rm -rf agent-sandbox nim-cache
