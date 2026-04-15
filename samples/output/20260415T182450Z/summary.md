# Sample Scan Summary

- Generated at: `2026-04-15T18:25:54.957888+00:00`
- Run directory: `output/20260415T182450Z`
- Total scans: `24`
- OK (exit 0/1): `22`
- Errors (exit 2+): `2`

## Per-scan Results

- `sast_python_command_injection` [filesystem] -> status=`ok` exit=`1` output=`output/20260415T182450Z/results/sast_python_command_injection.json` log=`output/20260415T182450Z/logs/sast_python_command_injection.log`
- `sast_python_eval_exec_injection` [filesystem] -> status=`ok` exit=`1` output=`output/20260415T182450Z/results/sast_python_eval_exec_injection.json` log=`output/20260415T182450Z/logs/sast_python_eval_exec_injection.log`
- `sast_python_sql_injection` [filesystem] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/sast_python_sql_injection.json` log=`output/20260415T182450Z/logs/sast_python_sql_injection.log`
- `sast_python_path_traversal` [filesystem] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/sast_python_path_traversal.json` log=`output/20260415T182450Z/logs/sast_python_path_traversal.log`
- `sast_python_weak_crypto` [filesystem] -> status=`ok` exit=`1` output=`output/20260415T182450Z/results/sast_python_weak_crypto.json` log=`output/20260415T182450Z/logs/sast_python_weak_crypto.log`
- `sast_python_safe_patterns` [filesystem] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/sast_python_safe_patterns.json` log=`output/20260415T182450Z/logs/sast_python_safe_patterns.log`
- `sca_python_vulnerable_deps` [filesystem] -> status=`ok` exit=`1` output=`output/20260415T182450Z/results/sca_python_vulnerable_deps.json` log=`output/20260415T182450Z/logs/sca_python_vulnerable_deps.log`
- `sca_python_safe_deps` [filesystem] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/sca_python_safe_deps.json` log=`output/20260415T182450Z/logs/sca_python_safe_deps.log`
- `iac_terraform_public_ingress` [filesystem] -> status=`ok` exit=`1` output=`output/20260415T182450Z/results/iac_terraform_public_ingress.json` log=`output/20260415T182450Z/logs/iac_terraform_public_ingress.log`
- `iac_terraform_unencrypted_storage` [filesystem] -> status=`ok` exit=`1` output=`output/20260415T182450Z/results/iac_terraform_unencrypted_storage.json` log=`output/20260415T182450Z/logs/iac_terraform_unencrypted_storage.log`
- `iac_terraform_safe_baseline` [filesystem] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/iac_terraform_safe_baseline.json` log=`output/20260415T182450Z/logs/iac_terraform_safe_baseline.log`
- `combined_flask_vulnerable_app_sast` [filesystem] -> status=`ok` exit=`1` output=`output/20260415T182450Z/results/combined_flask_vulnerable_app_sast.json` log=`output/20260415T182450Z/logs/combined_flask_vulnerable_app_sast.log`
- `combined_flask_safe_app_sast` [filesystem] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/combined_flask_safe_app_sast.json` log=`output/20260415T182450Z/logs/combined_flask_safe_app_sast.log`
- `combined_app_with_vulnerable_requirements_sast_sca` [filesystem] -> status=`error` exit=`2` output=`output/20260415T182450Z/results/combined_app_with_vulnerable_requirements_sast_sca.json` log=`output/20260415T182450Z/logs/combined_app_with_vulnerable_requirements_sast_sca.log`
- `combined_app_with_safe_terraform_sast_iac` [filesystem] -> status=`error` exit=`2` output=`output/20260415T182450Z/results/combined_app_with_safe_terraform_sast_iac.json` log=`output/20260415T182450Z/logs/combined_app_with_safe_terraform_sast_iac.log`
- `dast_simple_headers_app` [dast_http] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/dast_simple_headers_app.json` log=`output/20260415T182450Z/logs/dast_simple_headers_app.log`
- `dast_simple_reflection_app` [dast_http] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/dast_simple_reflection_app.json` log=`output/20260415T182450Z/logs/dast_simple_reflection_app.log`
- `dast_simple_error_leak_app` [dast_http] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/dast_simple_error_leak_app.json` log=`output/20260415T182450Z/logs/dast_simple_error_leak_app.log`
- `dast_simple_cors_app` [dast_http] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/dast_simple_cors_app.json` log=`output/20260415T182450Z/logs/dast_simple_cors_app.log`
- `dast_simple_api_target` [dast_http] -> status=`ok` exit=`1` output=`output/20260415T182450Z/results/dast_simple_api_target.json` log=`output/20260415T182450Z/logs/dast_simple_api_target.log`
- `combined_flask_vulnerable_app_dast` [dast_http] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/combined_flask_vulnerable_app_dast.json` log=`output/20260415T182450Z/logs/combined_flask_vulnerable_app_dast.log`
- `combined_flask_safe_app_dast` [dast_http] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/combined_flask_safe_app_dast.json` log=`output/20260415T182450Z/logs/combined_flask_safe_app_dast.log`
- `combined_app_with_vulnerable_requirements_dast` [dast_http] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/combined_app_with_vulnerable_requirements_dast.json` log=`output/20260415T182450Z/logs/combined_app_with_vulnerable_requirements_dast.log`
- `combined_app_with_safe_terraform_dast` [dast_http] -> status=`ok` exit=`0` output=`output/20260415T182450Z/results/combined_app_with_safe_terraform_dast.json` log=`output/20260415T182450Z/logs/combined_app_with_safe_terraform_dast.log`
