rule Filecoder_PromptLock_A
{
    strings:
        $model      = "gpt-oss:20b" ascii
        $ollama_api = "/ollama/v1/chat/completions" ascii
        $prompt_1   = "Implement the SPECK 128bit encryption algorithm" ascii
        $prompt_2   = "Please provide Lua code wrapped in <code></code> tags" ascii
        $lua_dep    = "yuin/gopher-lua" ascii
        $lfs_dep    = "layeh.com/gopher-lfs" ascii
        $bit32_dep  = "PeerDB-io/gluabit32" ascii
        $log_1      = "target_file_list.log" ascii
        $go_magic   = { 47 6F 20 62 75 69 6C 64 69 6E 66 3A }

    condition:
        uint32(0) == 0x464c457f and
        $go_magic and
        $model and
        ( $ollama_api or 1 of ($prompt_*) ) and
        2 of ($lua_dep, $lfs_dep, $bit32_dep, $log_1)
}