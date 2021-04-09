"""只读检查数据库完整性、外键及设计基线 SQL 校验和，不显示用户或秘密内容。"""
import argparse
import hashlib
from pathlib import Path
import sqlite3

def main():
    root=Path(__file__).resolve().parent.parent
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('database', nargs='?', default=str(root/'database'/'login.db'))
    path=Path(p.parse_args().database).resolve()
    if not path.is_file():
        raise SystemExit('数据库文件不存在')
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
    try:
        integrity=db.execute('PRAGMA integrity_check').fetchall()
        foreign=db.execute('PRAGMA foreign_key_check').fetchall()
        digest=db.execute('SELECT source_sha256 FROM schema_history WHERE version=?',('design-0001',)).fetchone()
        expected=hashlib.sha256((root/'database'/'0001_design_baseline.sql').read_bytes()).hexdigest()
        if integrity != [('ok',)] or foreign or not digest or digest[0]!=expected:
            raise SystemExit('检查失败：完整性、外键或结构基线摘要不符；请按迁移历史检查，勿覆盖已有库。')
        count=db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        print(f'检查通过：{count} 张表；完整性、外键与基线 SQL 摘要正常。')
    finally:
        db.close()
if __name__=='__main__':
    main()
