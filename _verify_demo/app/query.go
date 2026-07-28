package main

// SQL 拼接 —— 应报 SQL-INJECTION-RISK
func query(db interface{ Query(string) }, userId string) {
	db.Query("SELECT * FROM users WHERE id = " + userId)
}
