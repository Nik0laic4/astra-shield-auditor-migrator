#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI-точка входа: Astra Shield-Auditor & Migrator.

Примеры:
  python3 run_audit.py                                      # аудит (по SSH-ключу)
  python3 run_audit.py --json                               # аудит + сводка JSON
  python3 run_audit.py --fix --sudo-password YOUR_PASSWORD  # аудит + исправление
  python3 run_audit.py --export out.json --export out.csv   # экспорт результатов
  python3 run_audit.py --report ASTRA_SECURITY_REPORT.txt   # ГОСТ-отчёт
"""

import argparse
import json
import os
import sys
import time

from astra_shield import (MatrixAuditor, Migrator, export_report,
                          generate_gost_report)


def _print_summary(args, scan, scan_time, fix_results):
    if args.json:
        payload = scan.to_dict()
        payload["scan_time_sec"] = round(scan_time, 3)
        if fix_results:
            payload["fix"] = [f.to_dict() for f in fix_results]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    print("=" * 62)
    print("Astra Shield-Auditor & Migrator — аудит")
    print("=" * 62)
    print(f"Хост:        {args.user}@{args.host}")
    print(f"Корень:      {args.root}")
    print(f"Потоков:     {args.workers}")
    print(f"Время:       {scan_time:.2f} с")
    print("-" * 62)
    print(f"Всего файлов:                 {scan.total_files}")
    print(f"Всего каталогов:              {scan.total_dirs}")
    print(f"Файлов с DAC=777:             {scan.dac777_count}")
    print(f"Файлов с завыш. целостностью: {scan.elevated_integrity_count}")
    print(f"Конфликтов DAC/MAC:           {scan.conflict_count}")
    if fix_results:
        fixed = sum(1 for f in fix_results if f.ok)
        print("-" * 62)
        print(f"Исправлено конфликтов:        {fixed}/{len(fix_results)}")
    print("=" * 62)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Astra Shield-Auditor & Migrator — аудит и исправление test_matrix"
    )
    p.add_argument("--host", default="192.168.122.13")
    p.add_argument("--user", default="administr")
    p.add_argument("--password", default=None,
                   help="пароль SSH (если не используется ключ)")
    p.add_argument("--root", default="/home/administr/test_matrix")
    p.add_argument("--workers", type=int, default=16,
                   help="число потоков на удалённой стороне")
    p.add_argument("--json", action="store_true", help="сводка в JSON")
    p.add_argument("--scan", action="store_true",
                   help="режим сканирования (без исправления, по умолчанию)")
    p.add_argument("--fix", action="store_true",
                   help="исправить выявленные конфликты (Мигратор)")
    p.add_argument("--sudo-password", default=os.environ.get("SUDO_PASSWORD"),
                   help="пароль sudo для pdpl-file (или SUDO_PASSWORD)")
    p.add_argument("--export", action="append", default=[], metavar="PATH",
                   help="экспорт детального отчёта (.json или .csv); можно несколько")
    p.add_argument("--report", default="ASTRA_SECURITY_REPORT.txt", metavar="PATH",
                   help="путь к ГОСТ-отчёту")
    p.add_argument("--no-report", action="store_true",
                   help="не формировать ГОСТ-отчёт")
    args = p.parse_args()

    auditor = MatrixAuditor(args.host, args.user, password=args.password)

    t0 = time.time()
    scan = auditor.scan(args.root, workers=args.workers)
    scan_time = time.time() - t0

    fix_results = []
    if args.fix:
        if not args.sudo_password:
            print("ОШИБКА: --fix требует --sudo-password (или SUDO_PASSWORD).",
                  file=sys.stderr)
            return 2
        migrator = Migrator(args.host, args.user, password=args.password)
        fix_results = migrator.fix(scan.conflicts, args.sudo_password)

    _print_summary(args, scan, scan_time, fix_results)

    for path in args.export:
        try:
            export_report(scan, fix_results, path)
            print(f"[+] экспорт: {path}")
        except ValueError as exc:
            print(f"ОШИБКА экспорта: {exc}", file=sys.stderr)

    if not args.no_report:
        generate_gost_report(scan, fix_results, scan_time, args.workers,
                             args.host, args.user, args.root, args.report)
        print(f"[+] ГОСТ-отчёт: {args.report}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

