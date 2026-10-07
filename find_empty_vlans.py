import os
import sys
import json
from datetime import datetime
from netmiko import ConnectHandler

DEVICE = {
    "device_type": "juniper_junos",
    "host": "192.168.55.205",      # IP вашего QFX 
    "username": "Maks",            # имя пользователя
    "use_keys": True,              # использование SSH-ключа
    "key_file": "/home/maks/.ssh/id_rsa", # ключ SSH
    "disabled_algorithms": {"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
}

EXCLUDE_FILE = os.path.join(os.path.dirname(__file__), "exclude_vlans.txt")


def load_excluded_vlans(filepath):
    """
    Загружает список исключаемых VLAN из файла.
    Если файла нет, создает базовый файл с шаблоном.
    """
    excluded = set()
    if not os.path.exists(filepath):
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("# Файл исключений VLAN для проверок и команд удаления\n")
            f.write("# Укажите номера VLAN или их имена (по одному на строку)\n")
            f.write("1\ndefault\n")
        excluded.update(["1", "default", "vlan1"])
        return excluded

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            val = line.lower()
            excluded.add(val)
            if val.startswith("vlan") and val[4:].isdigit():
                excluded.add(val[4:])
            elif val.isdigit():
                excluded.add(f"vlan{val}")
    return excluded


def is_excluded(tag, name, excluded_set):
    """Проверяет, входит ли VLAN в список исключений."""
    tag_str = str(tag).strip().lower()
    name_str = str(name).strip().lower()
    return tag_str in excluded_set or name_str in excluded_set


def safe_navigate(obj, *keys):
    """Безопасно переходит по вложенным ключам словарей и списков."""
    cur = obj
    for key in keys:
        if cur is None:
            return None
        if isinstance(cur, list):
            if len(cur) == 0:
                return None
            cur = cur[0]
        if isinstance(cur, dict):
            cur = cur.get(key)
        else:
            return None
    return cur


def extract_value(data_field, default="—"):
    """Рекурсивно извлекает текстовое значение из различных структур Junos JSON."""
    if data_field is None:
        return default
    if isinstance(data_field, dict):
        val = data_field.get("data", default)
        return extract_value(val, default)
    if isinstance(data_field, list):
        if len(data_field) == 0:
            return default
        first = data_field[0]
        if first is None:
            return default
        if isinstance(first, dict):
            return extract_value(first.get("data", default), default)
        return extract_value(first, default)
    return str(data_field)


def parse_vlan_interfaces(vlans_data):
    """
    Собирает сопоставление VLAN -> список интерфейсов (портов)
    из вывода 'show vlans | display json'.
    """
    vlan_interfaces = {}

    # 1. Формат Junos ELS (QFX)
    els_vlans = safe_navigate(vlans_data, "l2ng-l2ald-vlan-instance-information", "l2ng-l2ald-vlan-instance-group")
    if els_vlans is not None:
        if isinstance(els_vlans, dict):
            els_vlans = [els_vlans]
        for v in els_vlans:
            v_name = extract_value(v.get("l2ng-l2rtb-vlan-name"), default="")
            v_tag = extract_value(v.get("l2ng-l2rtb-vlan-tag"), default="")
            members = v.get("l2ng-l2rtb-vlan-member", [])
            if isinstance(members, dict):
                members = [members]

            ifaces = []
            for m in members:
                iface_val = extract_value(m.get("l2ng-l2rtb-vlan-member-interface"), default=None)
                if iface_val and iface_val not in ("None", "null", "—"):
                    clean = iface_val.rstrip("*").strip()
                    if clean:
                        ifaces.append(clean)

            if v_name:
                vlan_interfaces[v_name] = ifaces
            if v_tag:
                vlan_interfaces[v_tag] = ifaces

    # 2. Формат Junos non-ELS
    legacy_vlans = safe_navigate(vlans_data, "vlans-information", "vlan-information")
    if legacy_vlans is not None:
        if isinstance(legacy_vlans, dict):
            legacy_vlans = [legacy_vlans]
        for v in legacy_vlans:
            v_name = extract_value(v.get("vlan-name"), default="")
            v_tag = extract_value(v.get("vlan-tag"), default="")
            members = v.get("vlan-member", [])
            if isinstance(members, dict):
                members = [members]

            ifaces = []
            for m in members:
                iface_val = extract_value(m.get("vlan-member-interface"), default=None)
                if iface_val and iface_val not in ("None", "null", "—"):
                    clean = iface_val.rstrip("*").strip()
                    if clean:
                        ifaces.append(clean)

            if v_name:
                vlan_interfaces[v_name] = ifaces
            if v_tag:
                vlan_interfaces[v_tag] = ifaces

    return vlan_interfaces


def parse_active_vlans(macs_data):
    """Возвращает множества имен и тегов VLAN, в которых изучены MAC-адреса."""
    active_names = set()
    active_tags = set()

    # 1. Junos ELS (QFX / EX4300 и др.)
    els_mac_groups = safe_navigate(macs_data, "l2ng-l2ald-rtb-macdb", "l2ng-l2ald-mac-entry-vlan") or []
    if isinstance(els_mac_groups, dict):
        els_mac_groups = [els_mac_groups]

    for item in els_mac_groups:
        vlan_id = extract_value(item.get("l2ng-l2-vlan-id"), default=None)
        if vlan_id:
            active_tags.add(str(vlan_id))

        entries = item.get("l2ng-mac-entry", [])
        if isinstance(entries, dict):
            entries = [entries]

        for entry in entries:
            v_name = extract_value(entry.get("l2ng-l2-mac-vlan-name"), default=None)
            if v_name:
                active_names.add(v_name)
                if v_name.lower().startswith("vlan") and v_name[4:].isdigit():
                    active_tags.add(v_name[4:])

    # 2. Junos non-ELS (старые EX)
    legacy_mac_entries = safe_navigate(
        macs_data, "ethernet-switching-table-information", "ethernet-switching-table", "mac-table-entry"
    ) or []
    if isinstance(legacy_mac_entries, dict):
        legacy_mac_entries = [legacy_mac_entries]

    for entry in legacy_mac_entries:
        vlan_name = extract_value(entry.get("mac-vlan-name"), default=None)
        if vlan_name:
            active_names.add(vlan_name)
            if vlan_name.lower().startswith("vlan") and vlan_name[4:].isdigit():
                active_tags.add(vlan_name[4:])

    return active_names, active_tags


def parse_configured_vlans(config_data, vlans_data=None):
    """Возвращает список кортежей (tag, name, desc) всех настроенных VLAN."""
    configured = []

    # 1. Извлекаем из конфигурации (где хранятся description)
    vlan_list = safe_navigate(config_data, "configuration", "vlans", "vlan")
    if vlan_list is not None:
        if isinstance(vlan_list, dict):
            vlan_list = [vlan_list]
        for v in vlan_list:
            name = extract_value(v.get("name"), default="N/A")
            tag = extract_value(v.get("vlan-id"), default="")
            if not tag or tag == "—":
                tag = extract_value(v.get("vlan-range"), default="untagged")
            desc = extract_value(v.get("description"), default="—")
            configured.append((str(tag), name, desc))

    if configured:
        return configured

    # 2. Fallback: Junos ELS операционный вывод (show vlans)
    els_vlans = safe_navigate(vlans_data, "l2ng-l2ald-vlan-instance-information", "l2ng-l2ald-vlan-instance-group")
    if els_vlans is not None:
        if isinstance(els_vlans, dict):
            els_vlans = [els_vlans]
        for v in els_vlans:
            name = extract_value(v.get("l2ng-l2rtb-vlan-name"), default="N/A")
            tag = extract_value(v.get("l2ng-l2rtb-vlan-tag"), default="untagged")
            desc = extract_value(v.get("l2ng-l2rtb-vlan-detail-description"), default="—")
            configured.append((str(tag), name, desc))

    return configured


def fetch_switch_data():
    """Подключается к коммутатору и забирает все необходимые данные за один сеанс."""
    print(f"Подключение к {DEVICE['host']}...")
    with ConnectHandler(**DEVICE) as conn:
        print("Получение конфигурации VLAN...")
        config_raw = conn.send_command("show configuration vlans | display json")
        print("Получение операционной таблицы VLAN и портов...")
        vlans_raw = conn.send_command("show vlans | display json")
        print("Получение таблицы MAC-адресов...")
        macs_raw = conn.send_command("show ethernet-switching table | display json")

    config_data = json.loads(config_raw)
    vlans_data = json.loads(vlans_raw)
    macs_data = json.loads(macs_raw)

    return config_data, vlans_data, macs_data


def print_empty_vlans_table(empty_vlans):
    """Выводит таблицу пустых VLAN без MAC-адресов."""
    print("\n" + "=" * 80)
    print(f"{'VLAN ID':<10} | {'VLAN NAME':<25} | {'DESCRIPTION'}")
    print("=" * 80)
    for tag, name, desc in empty_vlans:
        print(f"{tag:<10} | {name:<25} | {desc}")
    print("=" * 80)
    print(f"Всего пустых VLAN: {len(empty_vlans)}")


def save_and_print_delete_commands(empty_vlans, vlan_interfaces):
    """
    Выводит команды удаления в формате display set, сгруппированные по номеру VLAN
    и разделенные пустыми строками для удобного ручного выбора.
    Также сохраняет (дописывает) команды в текстовый файл вида sw200.txt (по последнему октету IP)
    с указанием заголовка, даты и времени генерации, а также команд восстановления (rollback).
    """
    host = DEVICE["host"]
    last_octet = host.split(".")[-1]
    filename = f"sw{last_octet}.txt"
    filepath = os.path.join(os.path.dirname(__file__), filename)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    file_header = (
        f"{'=' * 80}\n"
        f"# УСТРОЙСТВО: sw{last_octet} ({host})\n"
        f"# ДАТА И ВРЕМЯ ГЕНЕРАЦИИ: {now_str}\n"
        f"# ВСЕГО ПУСТЫХ VLAN ДЛЯ УДАЛЕНИЯ: {len(empty_vlans)}\n"
        f"{'=' * 80}\n\n"
    )

    file_sections = [file_header]
    console_sections = [
        "\n" + "=" * 80,
        f"КОМАНДЫ ДЛЯ УДАЛЕНИЯ (в формате display set) [sw{last_octet}]:",
        "=" * 80 + "\n"
    ]

    for tag, name, desc in empty_vlans:
        # Ищем привязанные интерфейсы
        ifaces = vlan_interfaces.get(name) or vlan_interfaces.get(tag) or []
        member_target = tag if tag != "untagged" else name

        del_lines = []
        restore_iface_lines = []

        for iface_str in ifaces:
            clean_iface = iface_str.rstrip("*").strip()
            if "." in clean_iface:
                port, unit = clean_iface.rsplit(".", 1)
            else:
                port, unit = clean_iface, "0"
            del_lines.append(f"delete interfaces {port} unit {unit} family ethernet-switching vlan members {member_target}")
            restore_iface_lines.append(f"set interfaces {port} unit {unit} family ethernet-switching vlan members {member_target}")

        del_lines.append(f"delete vlans {name}")

        # Формируем команды восстановления (set)
        vlan_restore_lines = []
        if tag != "untagged":
            vlan_restore_lines.append(f"set vlans {name} vlan-id {tag}")
        else:
            vlan_restore_lines.append(f"set vlans {name}")
        if desc and desc != "—":
            vlan_restore_lines.append(f'set vlans {name} description "{desc}"')

        all_restore_lines = vlan_restore_lines + restore_iface_lines

        # Блок для вывода в консоль
        console_block = f"# VLAN {tag} ({name}) - {desc}\n" + "\n".join(del_lines)
        console_sections.append(console_block)

        # Блок для сохранения в файл (с командами отката)
        file_block = (
            f"# ------------------------------------------------------------------------------\n"
            f"# VLAN {tag} ({name}) - {desc}\n"
            f"# ------------------------------------------------------------------------------\n"
            + "\n".join(del_lines) + "\n\n"
            + "# Команды для восстановления (ROLLBACK / ВЕРНУТЬ НАЗАД):\n"
            + "\n".join(all_restore_lines) + "\n"
        )
        file_sections.append(file_block)

    # Вывод в консоль
    print("\n\n".join(console_sections))

    # Сохранение в файл sw<одно_число>.txt (режим append для сохранения истории)
    with open(filepath, "a", encoding="utf-8") as f:
        f.write("\n\n".join(file_sections) + "\n\n")

    print("\n" + "=" * 80)
    print(f"✓ Команды удаления и команды для восстановления сохранены в файл:")
    print(f"  {filepath}")
    print("=" * 80)


def main():
    excluded_vlans = load_excluded_vlans(EXCLUDE_FILE)
    print(f"Загружено исключений VLAN: {len(excluded_vlans)} из {os.path.basename(EXCLUDE_FILE)}")

    # 1. Забираем данные с коммутатора
    config_data, vlans_data, macs_data = fetch_switch_data()

    # 2. Разбираем данные
    active_names, active_tags = parse_active_vlans(macs_data)
    configured_vlans = parse_configured_vlans(config_data, vlans_data)
    vlan_interfaces = parse_vlan_interfaces(vlans_data)

    # 3. Фильтруем пустые VLAN, исключая те, что в файле исключений
    empty_vlans = []
    for tag, name, desc in configured_vlans:
        if is_excluded(tag, name, excluded_vlans):
            continue
        if name not in active_names and tag not in active_tags:
            empty_vlans.append((tag, name, desc))

    # Сортировка по числовому VLAN ID
    def sort_key(item):
        try:
            return (0, int(item[0]))
        except ValueError:
            return (1, item[0])

    empty_vlans.sort(key=sort_key)

    # 4. Проверяем аргументы командной строки или запрашиваем меню
    choice = None
    if len(sys.argv) > 1:
        choice = sys.argv[1].strip()

    while choice not in ("1", "2"):
        print("\n" + "=" * 50)
        print("ВЫБЕРИТЕ ДЕЙСТВИЕ:")
        print("  1. Вывести VLAN без MAC-адресов")
        print("  2. Вывести команды удаления (delete)")
        print("  0. Выход")
        print("=" * 50)
        choice = input("Ваш выбор [1/2/0]: ").strip()
        if choice == "0":
            print("Выход.")
            return

    if choice == "1":
        print_empty_vlans_table(empty_vlans)
    elif choice == "2":
        save_and_print_delete_commands(empty_vlans, vlan_interfaces)


if __name__ == "__main__":
    main()
