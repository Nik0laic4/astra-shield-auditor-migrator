#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Astra Shield-Auditor & Migrator — генератор тестовой среды («цифровой хаос»).

Создаёт изолированное дерево каталогов test_matrix и ровно N текстовых файлов
(до 1 КБ каждый). Часть файлов («дефекты») получает скрытый архитектурный
конфликт PARSEC:
  * дискреционные права (DAC) — 777 (открыто для всех);
  * мандатная целостность (MAC) — искусственно завышена (Низкий -> Высокий, 63)
    через /sbin/pdpl-file (требует sudo).

По модели Biba (no write-up) процесс с низкой целостностью не сможет писать
в такой файл, несмотря на 777 — это и есть «скрытый конфликт» DAC vs MAC.

Требования: python3 (3.8+), sudo с паролем (для завышения меток).
Пароль sudo передаётся через --sudo-password или переменную окружения
SUDO_PASSWORD.
"""

import argparse
import json
import os
import random
import shutil
import string
import subprocess
import sys

SECTORS = 10
CLUSTERS = 10
NODES = 10
FILES_PER_NODE = 10                # 10 * 10 * 10 * 10 = 10000 файлов
RAISED_INTEGRITY_LABEL = "0:63"    # Уровень_0 : Высокий (целостность 63)
PDPL_FILE = "/sbin/pdpl-file"


def random_text(max_bytes: int = 1024) -> str:
    """Случайный текстовый фрагмент размером 64..max_bytes байт."""
    size = random.randint(64, max_bytes)
    alphabet = string.ascii_letters + string.digits + " \n.,;:-_[](){}"
    return "".join(random.choices(alphabet, k=size))


def build_tree(root: str, files_per_node: int):
    """Создаёт дерево 10 секторов x 10 кластеров x 10 узлов и возвращает пути файлов."""
    os.makedirs(root, exist_ok=True)
    paths = []
    for s in range(SECTORS):
        sector = os.path.join(root, f"sector_{s:02d}")
        for c in range(CLUSTERS):
            cluster = os.path.join(sector, f"cluster_{c:02d}")
            for n in range(NODES):
                node = os.path.join(cluster, f"node_{n:02d}")
                os.makedirs(node, exist_ok=True)
                for f in range(files_per_node):
                    idx = ((s * CLUSTERS + c) * NODES + n) * files_per_node + f
                    path = os.path.join(node, f"file_{idx:06d}.txt")
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(random_text())
                    paths.append(path)
    return paths


def _sudo(sudo_password: str, *cmd: str):
    """Запуск команды под sudo с паролем через stdin. Возвращает (ok, stderr)."""
    proc = subprocess.run(
        ["sudo", "-S", "-p", "", *cmd],
        input=sudo_password + "\n", text=True, capture_output=True,
    )
    err = (proc.stderr or "").strip()
    ok = proc.returncode == 0 and "Отказано" not in err
    return ok, err


def raise_dirs_integrity(root: str, sudo_password: str):
    """Поднимает целостность всех каталогов дерева до Высокий (top-down)."""
    return _sudo(sudo_password, "find", root, "-type", "d",
                 "-exec", PDPL_FILE, RAISED_INTEGRITY_LABEL, "{}", "+")


def raise_files_integrity(paths, sudo_password: str):
    """Поднимает целостность указанных файлов до Высокий."""
    return _sudo(sudo_password, PDPL_FILE, RAISED_INTEGRITY_LABEL, *paths)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Генератор 'цифрового хаоса' для Astra Shield-Auditor & Migrator"
    )
    p.add_argument("--root", default="/home/administr/test_matrix",
                   help="корень тестового дерева")
    p.add_argument("--files-per-node", type=int, default=FILES_PER_NODE,
                   help="файлов в каждом узле")
    p.add_argument("--defects", type=int, default=50,
                   help="количество дефектных файлов")
    p.add_argument("--seed", type=int, default=None,
                   help="зерно ГПСЧ (для воспроизводимости)")
    p.add_argument("--manifest", default="/home/administr/chaos_manifest.json",
                   help="путь к манифесту")
    p.add_argument("--sudo-password", default=os.environ.get("SUDO_PASSWORD"),
                   help="пароль sudo (или переменная SUDO_PASSWORD)")
    p.add_argument("--force", action="store_true",
                   help="пересоздать, если каталог уже существует")
    args = p.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if os.path.exists(args.root):
        if not args.force:
            print(f"ОШИБКА: {args.root} уже существует. Используйте --force.",
                  file=sys.stderr)
            return 2
        shutil.rmtree(args.root)
        print(f"[*] удалён существующий {args.root}")

    total = SECTORS * CLUSTERS * NODES * args.files_per_node
    print(f"[*] структура: {SECTORS} секторов x {CLUSTERS} кластеров x "
          f"{NODES} узлов x {args.files_per_node} файлов = {total}")
    files = build_tree(args.root, args.files_per_node)
    dirs = SECTORS + SECTORS * CLUSTERS + SECTORS * CLUSTERS * NODES
    print(f"[+] каталогов: {dirs + 1} (включая корень), файлов: {len(files)}")

    defects = random.sample(files, min(args.defects, len(files)))
    for path in defects:
        os.chmod(path, 0o777)                 # DAC: открыть для всех

    # PARSEC (Biba no-write-up): целостность файла не может превышать
    # целостность родительского каталога. Поэтому сначала поднимаем
    # целостность всех каталогов дерева до Высокий (top-down, через find),
    # затем — целостность самих дефектных файлов.
    labeled = 0
    defect_report = []
    if args.sudo_password:
        dirs_ok, dirs_err = raise_dirs_integrity(args.root, args.sudo_password)
        if dirs_ok:
            files_ok, files_err = raise_files_integrity(defects, args.sudo_password)
            if files_ok:
                labeled = len(defects)
                for path in defects:
                    defect_report.append({"path": path, "status": "label_raised",
                                          "error": ""})
            else:
                for path in defects:
                    defect_report.append({"path": path, "status": "label_failed",
                                          "error": files_err})
        else:
            for path in defects:
                defect_report.append({"path": path, "status": "chmod_only",
                                      "error": "каталоги не подняты: " + dirs_err})
    else:
        for path in defects:
            defect_report.append({"path": path, "status": "chmod_only",
                                  "error": "SUDO_PASSWORD не задан — метка НЕ завышена"})

    manifest = {
        "root": args.root,
        "total_files": len(files),
        "total_dirs": dirs + 1,
        "defects_total": len(defect_report),
        "defects_labeled_ok": labeled,
        "defect_mechanism": "chmod 777 + pdpl-file 0:63 (целостность Низкий->Высокий; каталоги дерева подняты до Высокий)",
        "seed": args.seed,
        "defects": defect_report,
    }
    with open(args.manifest, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)

    print(f"[+] манифест: {args.manifest}")
    print(f"[+] дефектов: {len(defect_report)} (метка завышена у {labeled}, "
          f"chmod 777 у всех)")
    print("ГОТОВО.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
