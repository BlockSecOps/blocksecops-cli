-- BlockSecOps - Neovim plugin for smart contract security scanning
-- Provides integration with blocksecops-cli for Solidity security analysis

local M = {}

-- Default configuration
M.config = {
    cli_path = "blocksecops",
    output_format = "sarif",
    scan_on_save = false,
    severity_threshold = "low",
}

-- Namespace for virtual text and diagnostics
local ns_id = vim.api.nvim_create_namespace("blocksecops")

-- Setup function to be called by users
function M.setup(opts)
    opts = opts or {}
    M.config = vim.tbl_deep_extend("force", M.config, opts)

    -- Create commands
    vim.api.nvim_create_user_command("BlockSecOpsScan", M.scan_current_file, {})
    vim.api.nvim_create_user_command("BlockSecOpsScanWorkspace", M.scan_workspace, {})
    vim.api.nvim_create_user_command("BlockSecOpsClear", M.clear_diagnostics, {})

    -- Auto-scan on save if enabled
    if M.config.scan_on_save then
        vim.api.nvim_create_autocmd("BufWritePost", {
            pattern = "*.sol",
            callback = function()
                M.scan_current_file()
            end,
        })
    end
end

-- Scan the current file
function M.scan_current_file()
    local bufnr = vim.api.nvim_get_current_buf()
    local file_path = vim.api.nvim_buf_get_name(bufnr)

    if file_path == "" or not file_path:match("%.sol$") then
        vim.notify("BlockSecOps: Not a Solidity file", vim.log.levels.WARN)
        return
    end

    vim.notify("BlockSecOps: Scanning...", vim.log.levels.INFO)

    local cmd = {
        M.config.cli_path,
        "scan",
        "run",
        file_path,
        "--output",
        "sarif",
    }

    vim.fn.jobstart(cmd, {
        stdout_buffered = true,
        on_stdout = function(_, data)
            if data and #data > 0 then
                local output = table.concat(data, "\n")
                vim.schedule(function()
                    M.process_results(output, bufnr)
                end)
            end
        end,
        on_exit = function(_, exit_code)
            if exit_code ~= 0 and exit_code ~= 1 then
                vim.schedule(function()
                    vim.notify(
                        "BlockSecOps: Scan failed with exit code " .. exit_code,
                        vim.log.levels.ERROR
                    )
                end)
            end
        end,
    })
end

-- Scan the workspace
function M.scan_workspace()
    local cwd = vim.fn.getcwd()
    vim.notify("BlockSecOps: Scanning workspace...", vim.log.levels.INFO)

    local cmd = {
        M.config.cli_path,
        "scan",
        "run",
        cwd,
        "--output",
        "sarif",
    }

    vim.fn.jobstart(cmd, {
        stdout_buffered = true,
        on_stdout = function(_, data)
            if data and #data > 0 then
                local output = table.concat(data, "\n")
                vim.schedule(function()
                    M.process_workspace_results(output)
                end)
            end
        end,
        on_exit = function(_, exit_code)
            if exit_code ~= 0 and exit_code ~= 1 then
                vim.schedule(function()
                    vim.notify(
                        "BlockSecOps: Workspace scan failed with exit code " .. exit_code,
                        vim.log.levels.ERROR
                    )
                end)
            end
        end,
    })
end

-- Process scan results and set diagnostics
function M.process_results(sarif_json, bufnr)
    M.clear_diagnostics()

    local findings = M.parse_sarif(sarif_json, bufnr)

    if #findings == 0 then
        vim.notify("BlockSecOps: No issues found", vim.log.levels.INFO)
        return
    end

    -- Convert to Neovim diagnostics format
    local diagnostics = {}
    for _, finding in ipairs(findings) do
        table.insert(diagnostics, {
            bufnr = bufnr,
            lnum = finding.lnum - 1,  -- 0-indexed
            col = finding.col - 1,
            end_lnum = finding.end_lnum and (finding.end_lnum - 1) or nil,
            severity = M.get_severity(finding.level),
            source = "blocksecops",
            message = finding.message,
            code = finding.rule_id,
        })
    end

    vim.diagnostic.set(ns_id, bufnr, diagnostics)
    vim.notify(
        string.format("BlockSecOps: %d issue(s) found", #findings),
        vim.log.levels.WARN
    )
end

-- Process workspace results
function M.process_workspace_results(sarif_json)
    local findings = M.parse_sarif(sarif_json)

    if #findings == 0 then
        vim.notify("BlockSecOps: No issues found", vim.log.levels.INFO)
        return
    end

    -- Populate quickfix list
    local qf_items = {}
    for _, finding in ipairs(findings) do
        table.insert(qf_items, {
            filename = finding.filename,
            lnum = finding.lnum,
            col = finding.col,
            type = finding.level == "error" and "E" or (finding.level == "warning" and "W" or "I"),
            text = string.format("[%s] %s", finding.rule_id, finding.message),
        })
    end

    vim.fn.setqflist(qf_items, "r")
    vim.notify(
        string.format("BlockSecOps: %d issue(s) found. Use :copen to view.", #findings),
        vim.log.levels.WARN
    )
    vim.cmd("copen")
end

-- Parse SARIF JSON output
function M.parse_sarif(sarif_json, filter_bufnr)
    local findings = {}

    local ok, sarif = pcall(vim.json.decode, sarif_json)
    if not ok or not sarif or not sarif.runs then
        return findings
    end

    local filter_file = filter_bufnr and vim.api.nvim_buf_get_name(filter_bufnr) or nil

    for _, run in ipairs(sarif.runs) do
        if run.results then
            for _, result in ipairs(run.results) do
                local finding = M.parse_finding(result, filter_file)
                if finding then
                    table.insert(findings, finding)
                end
            end
        end
    end

    return findings
end

-- Parse a single finding
function M.parse_finding(result, filter_file)
    if not result.locations or #result.locations == 0 then
        return nil
    end

    local location = result.locations[1]
    if not location.physicalLocation then
        return nil
    end

    local phys = location.physicalLocation
    local file = ""

    if phys.artifactLocation and phys.artifactLocation.uri then
        file = phys.artifactLocation.uri:gsub("^file://", "")
    end

    -- Filter by file if specified
    if filter_file and file ~= filter_file then
        return nil
    end

    local lnum = 1
    local col = 1
    local end_lnum = nil

    if phys.region then
        lnum = phys.region.startLine or 1
        col = phys.region.startColumn or 1
        end_lnum = phys.region.endLine
    end

    local level = result.level or "warning"
    local message = ""

    if result.message and result.message.text then
        message = result.message.text
    end

    return {
        filename = file,
        lnum = lnum,
        col = col,
        end_lnum = end_lnum,
        level = level,
        message = message,
        rule_id = result.ruleId or "unknown",
    }
end

-- Map SARIF level to Neovim diagnostic severity
function M.get_severity(level)
    local severity_map = {
        error = vim.diagnostic.severity.ERROR,
        warning = vim.diagnostic.severity.WARN,
        note = vim.diagnostic.severity.INFO,
    }
    return severity_map[level] or vim.diagnostic.severity.HINT
end

-- Clear all diagnostics
function M.clear_diagnostics()
    vim.diagnostic.reset(ns_id)
end

return M
