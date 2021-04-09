"""从结构 SQL 创建全新 SQLite 数据库；绝不覆盖已有文件。Python 仅用于启动包工具，产品仍为 Go。"""
import argparse
import datetime
import hashlib
from pathlib import Path
import sqlite3

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='新数据库路径，必须不存在')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    sql_path = root / 'database' / '0001_design_baseline.sql'
    data = sql_path.read_bytes()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    # 排他创建，避免意外覆盖已有库。
    with output.open('xb'):
        pass
    try:
        with sqlite3.connect(output) as db:
            db.executescript(data.decode('utf-8'))
            db.execute('INSERT INTO schema_history VALUES(?,?,?,?)',
                       ('design-0001', '设计基线；非 Go 迁移执行器已执行状态',
                        int(datetime.datetime.now(datetime.timezone.utc).timestamp()*1000),
                        hashlib.sha256(data).hexdigest()))
            if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('完整性检查失败')
            if db.execute('PRAGMA foreign_key_check').fetchall():
                raise RuntimeError('外键检查失败')
        print(f'创建成功：{output}')
    except Exception:
        # 保留失败文件供检查，绝不自动覆盖或再次尝试原路径。
        print(f'创建失败，可能存在未完成文件，请检查：{output}')
        raise

if __name__ == '__main__':
    main()
