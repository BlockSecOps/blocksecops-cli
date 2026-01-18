" BlockSecOps - Vim plugin for smart contract security scanning
" Maintainer: BlockSecOps Team
" Version: 1.0.0

if exists('g:loaded_blocksecops')
    finish
endif
let g:loaded_blocksecops = 1

" Configuration variables
if !exists('g:blocksecops_cli_path')
    let g:blocksecops_cli_path = 'blocksecops'
endif

if !exists('g:blocksecops_output_format')
    let g:blocksecops_output_format = 'sarif'
endif

if !exists('g:blocksecops_scan_on_save')
    let g:blocksecops_scan_on_save = 0
endif

" Signs for gutter marks
sign define BlockSecOpsError text=>> texthl=ErrorMsg linehl=
sign define BlockSecOpsWarning text=>> texthl=WarningMsg linehl=
sign define BlockSecOpsInfo text=>> texthl=Question linehl=

" Main scan command
command! -nargs=0 BlockSecOpsScan call blocksecops#ScanCurrentFile()
command! -nargs=0 BlockSecOpsScanWorkspace call blocksecops#ScanWorkspace()
command! -nargs=0 BlockSecOpsClearSigns call blocksecops#ClearSigns()

" Auto-scan on save (if enabled)
augroup BlockSecOps
    autocmd!
    autocmd BufWritePost *.sol if g:blocksecops_scan_on_save | call blocksecops#ScanCurrentFile() | endif
augroup END

" Scan the current file
function! blocksecops#ScanCurrentFile() abort
    let l:file = expand('%:p')
    if l:file == '' || fnamemodify(l:file, ':e') != 'sol'
        echohl WarningMsg
        echo 'BlockSecOps: Not a Solidity file'
        echohl None
        return
    endif

    echo 'BlockSecOps: Scanning...'

    let l:cmd = [g:blocksecops_cli_path, 'scan', 'run', l:file, '--output', 'sarif']
    let l:output = system(join(l:cmd, ' '))
    let l:exit_code = v:shell_error

    if l:exit_code == 0 || l:exit_code == 1
        call blocksecops#ProcessResults(l:output, l:file)
    else
        echohl ErrorMsg
        echo 'BlockSecOps: Scan failed with exit code ' . l:exit_code
        echohl None
    endif
endfunction

" Scan the workspace
function! blocksecops#ScanWorkspace() abort
    let l:dir = getcwd()
    echo 'BlockSecOps: Scanning workspace...'

    let l:cmd = [g:blocksecops_cli_path, 'scan', 'run', l:dir, '--output', 'sarif']
    let l:output = system(join(l:cmd, ' '))
    let l:exit_code = v:shell_error

    if l:exit_code == 0 || l:exit_code == 1
        call blocksecops#ProcessWorkspaceResults(l:output)
    else
        echohl ErrorMsg
        echo 'BlockSecOps: Workspace scan failed with exit code ' . l:exit_code
        echohl None
    endif
endfunction

" Process SARIF results and populate quickfix list
function! blocksecops#ProcessResults(sarif_json, current_file) abort
    call blocksecops#ClearSigns()

    let l:findings = blocksecops#ParseSarif(a:sarif_json, a:current_file)

    if empty(l:findings)
        echo 'BlockSecOps: No issues found'
        return
    endif

    " Add signs
    let l:sign_id = 1
    for l:finding in l:findings
        let l:sign_name = 'BlockSecOps' . l:finding.level
        execute 'sign place ' . l:sign_id . ' line=' . l:finding.lnum . ' name=' . l:sign_name . ' buffer=' . bufnr('%')
        let l:sign_id += 1
    endfor

    " Populate quickfix list
    call setqflist(l:findings, 'r')
    echo 'BlockSecOps: ' . len(l:findings) . ' issue(s) found. Use :copen to view.'
endfunction

" Process workspace results
function! blocksecops#ProcessWorkspaceResults(sarif_json) abort
    let l:findings = blocksecops#ParseSarif(a:sarif_json, '')

    if empty(l:findings)
        echo 'BlockSecOps: No issues found'
        return
    endif

    call setqflist(l:findings, 'r')
    echo 'BlockSecOps: ' . len(l:findings) . ' issue(s) found. Use :copen to view.'
    copen
endfunction

" Parse SARIF JSON output
function! blocksecops#ParseSarif(sarif_json, filter_file) abort
    let l:findings = []

    try
        let l:sarif = json_decode(a:sarif_json)
    catch
        return l:findings
    endtry

    if !has_key(l:sarif, 'runs') || empty(l:sarif.runs)
        return l:findings
    endif

    for l:run in l:sarif.runs
        if !has_key(l:run, 'results')
            continue
        endif

        for l:result in l:run.results
            let l:finding = blocksecops#ParseFinding(l:result, a:filter_file)
            if !empty(l:finding)
                call add(l:findings, l:finding)
            endif
        endfor
    endfor

    return l:findings
endfunction

" Parse a single finding from SARIF result
function! blocksecops#ParseFinding(result, filter_file) abort
    if !has_key(a:result, 'locations') || empty(a:result.locations)
        return {}
    endif

    let l:location = a:result.locations[0]
    if !has_key(l:location, 'physicalLocation')
        return {}
    endif

    let l:phys = l:location.physicalLocation
    let l:file = ''

    if has_key(l:phys, 'artifactLocation') && has_key(l:phys.artifactLocation, 'uri')
        let l:file = substitute(l:phys.artifactLocation.uri, '^file://', '', '')
    endif

    " Filter by file if specified
    if a:filter_file != '' && l:file != a:filter_file && !stridx(a:filter_file, l:file)
        return {}
    endif

    let l:lnum = 1
    let l:col = 1
    if has_key(l:phys, 'region')
        let l:region = l:phys.region
        let l:lnum = get(l:region, 'startLine', 1)
        let l:col = get(l:region, 'startColumn', 1)
    endif

    let l:level = get(a:result, 'level', 'warning')
    let l:type = l:level == 'error' ? 'E' : (l:level == 'warning' ? 'W' : 'I')

    let l:message = ''
    if has_key(a:result, 'message') && has_key(a:result.message, 'text')
        let l:message = a:result.message.text
    endif

    let l:rule_id = get(a:result, 'ruleId', 'unknown')

    return {
        \ 'filename': l:file,
        \ 'lnum': l:lnum,
        \ 'col': l:col,
        \ 'type': l:type,
        \ 'text': '[' . l:rule_id . '] ' . l:message,
        \ 'level': l:level == 'error' ? 'Error' : (l:level == 'warning' ? 'Warning' : 'Info')
        \ }
endfunction

" Clear all BlockSecOps signs
function! blocksecops#ClearSigns() abort
    execute 'sign unplace * group=BlockSecOps'
endfunction

" ALE integration (if ALE is installed)
if exists('g:ale_enabled')
    function! blocksecops#ALELinter(buffer) abort
        let l:file = bufname(a:buffer)
        return {
            \ 'command': g:blocksecops_cli_path . ' scan run %s --output sarif',
            \ 'callback': 'blocksecops#ALEHandler',
            \ 'output_stream': 'stdout'
            \ }
    endfunction

    function! blocksecops#ALEHandler(buffer, lines) abort
        let l:output = join(a:lines, "\n")
        let l:findings = blocksecops#ParseSarif(l:output, bufname(a:buffer))
        let l:ale_results = []

        for l:finding in l:findings
            call add(l:ale_results, {
                \ 'lnum': l:finding.lnum,
                \ 'col': l:finding.col,
                \ 'type': l:finding.type,
                \ 'text': l:finding.text
                \ })
        endfor

        return l:ale_results
    endfunction

    " Register with ALE
    call ale#linter#Define('solidity', {
        \ 'name': 'blocksecops',
        \ 'lsp': '',
        \ 'executable': g:blocksecops_cli_path,
        \ 'command': g:blocksecops_cli_path . ' scan run %s --output sarif',
        \ 'callback': 'blocksecops#ALEHandler'
        \ })
endif
