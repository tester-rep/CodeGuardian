# 行内豁免 —— 不应报（Phase 2.1）
token = "realSecret999"  # codeguardian: ignore HARDCODED-PASSWORD

# 无豁免 —— 应报 HARDCODED-PASSWORD
backup_token = "realSecret888"
