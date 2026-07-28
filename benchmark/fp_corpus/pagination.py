def list_all(repo):
    # TP-1: find_all 无分页（应报 MISSING-PAGINATION）
    return repo.find_all()


def list_paged(repo, pageable):
    # FP-1: find_all 带分页参数（不应报）
    return repo.find_all(pageable)
