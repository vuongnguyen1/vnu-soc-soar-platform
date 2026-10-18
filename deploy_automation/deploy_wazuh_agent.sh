#!/usr/bin/env bash
# ==============================================================================
# SCRIPT TRIỂN KHAI CÀI ĐẶT WAZUH AGENT AN TOÀN
# Đường dẫn: /var/ossec/agent_deploy/deploy_wazuh_agent.sh
# ==============================================================================

set -e

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="${BASE_DIR}/.secrets"
SECRETS_FILE="${SECRETS_DIR}/.env_secrets"
INVENTORY_FILE="${BASE_DIR}/inventory.ini"
SERVERS_MD="${BASE_DIR}/servers.md"
CONFIG_FILE="${BASE_DIR}/config.env"
SCRIPTS_DIR="${BASE_DIR}/scripts"

# Load cấu hình chung
if [ -f "${CONFIG_FILE}" ]; then
    source "${CONFIG_FILE}"
fi

WAZUH_MANAGER_IP="${WAZUH_MANAGER_IP:-10.0.0.10}"
WAZUH_AGENT_VERSION="${WAZUH_AGENT_VERSION:-4.9.0}"

# Màu sắc
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

TARGET="$1"

if [ -z "${TARGET}" ]; then
    echo -e "${RED}Lỗi: Chưa chỉ định máy chủ cần cài đặt Wazuh Agent.${NC}"
    echo -e "Cú pháp: $0 <hostname_hoặc_ip>"
    echo -e "Ví dụ:   $0 web-prod"
    echo -e "         $0 192.168.1.10"
    exit 1
fi

echo -e "\n${BOLD}${CYAN}============================================================${NC}"
echo -e "${BOLD}${CYAN}   BẮT ĐẦU TRIỂN KHAI WAZUH AGENT TỚI: ${YELLOW}${TARGET}${NC}"
echo -e "${BOLD}${CYAN}   WAZUH MANAGER SẼ KẾT NỐI VỀ:        ${GREEN}${WAZUH_MANAGER_IP}${NC}"
echo -e "${BOLD}${CYAN}============================================================${NC}\n"

# 1. Tìm máy chủ trong inventory.ini
LINE=$(grep -E "(^${TARGET}\s|ansible_host=${TARGET}(\s|$))" "${INVENTORY_FILE}" | head -n 1)

if [ -z "${LINE}" ]; then
    echo -e "${RED}[LỖI] Không tìm thấy máy chủ '${TARGET}' trong file cấu hình inventory.ini!${NC}"
    echo -e "Vui lòng thêm máy chủ bằng lệnh: ${YELLOW}${BASE_DIR}/manage_hosts.sh add${NC}"
    exit 1
fi

HOST_NAME=$(echo "${LINE}" | awk '{print $1}')
HOST_IP=$(echo "${LINE}" | grep -o 'ansible_host=[^ ]*' | cut -d'=' -f2)
HOST_PORT=$(echo "${LINE}" | grep -o 'ansible_port=[^ ]*' | cut -d'=' -f2)
HOST_USER=$(echo "${LINE}" | grep -o 'ansible_user=[^ ]*' | cut -d'=' -f2)
OS_TYPE=$(echo "${LINE}" | grep -o 'os_type=[^ ]*' | cut -d'=' -f2)

[ -z "${OS_TYPE}" ] && OS_TYPE="linux"
[ -z "${HOST_PORT}" ] && HOST_PORT="22"

echo -e "Thông tin mục tiêu:"
echo -e "  - Tên máy:  ${BOLD}${HOST_NAME}${NC}"
echo -e "  - Địa chỉ:  ${BOLD}${HOST_IP}:${HOST_PORT}${NC}"
echo -e "  - Hệ điều hành: ${BOLD}${OS_TYPE}${NC}"
echo -e "  - Tài khoản: ${BOLD}${HOST_USER}${NC}\n"

# 2. Lấy mật khẩu an toàn từ .env_secrets (không in ra màn hình)
to_env_var_name() {
    echo "$1" | sed -e 's/[^a-zA-Z0-9_]/_/g'
}

VAR_KEY="PASS_$(to_env_var_name "${HOST_NAME}")"
VAR_IP_KEY="PASS_$(to_env_var_name "${HOST_IP}")"
HOST_PASS=""

if [ -f "${SECRETS_FILE}" ]; then
    HOST_PASS=$(bash -c "source '${SECRETS_FILE}'; echo \${${VAR_KEY}:-\${${VAR_IP_KEY}}}")
fi

if [ -z "${HOST_PASS}" ]; then
    echo -e "${RED}[LỖI BẢO MẬT] Không tìm thấy thông tin xác thực cho máy chủ trong ${SECRETS_FILE}!${NC}"
    exit 1
fi

DEPLOY_SUCCESS=0

# 3. Thử dùng Ansible nếu có sẵn
if command -v ansible-playbook >/dev/null 2>&1; then
    echo -e "${YELLOW}[...] Triển khai tự động bằng Ansible Playbook...${NC}"
    export ANSIBLE_HOST_KEY_CHECKING=False
    export WAZUH_MANAGER_IP
    export WAZUH_AGENT_VERSION

    if [ "${OS_TYPE}" == "windows" ]; then
        if ansible-playbook -i "${INVENTORY_FILE}" "${BASE_DIR}/playbooks/install_agent.yml" \
            --limit "${HOST_NAME}" \
            -e "ansible_password='${HOST_PASS}' ansible_port=${HOST_PORT}"; then
            DEPLOY_SUCCESS=1
        fi
    else
        if ansible-playbook -i "${INVENTORY_FILE}" "${BASE_DIR}/playbooks/install_agent.yml" \
            --limit "${HOST_NAME}" \
            -e "ansible_password='${HOST_PASS}' ansible_become_password='${HOST_PASS}'"; then
            DEPLOY_SUCCESS=1
        fi
    fi
fi

# 4. Fallback dùng deploy_runner.py nếu Ansible chưa cài hoặc không thành công
if [ "${DEPLOY_SUCCESS}" -eq 0 ]; then
    echo -e "${YELLOW}[...] Chạy trình triển khai trực tiếp độc lập...${NC}"
    PYTHON_BIN="/usr/bin/python3"
    if [ -x "/var/ossec/framework/python/bin/python3" ]; then
        PYTHON_BIN="/var/ossec/framework/python/bin/python3"
    fi

    if "${PYTHON_BIN}" "${SCRIPTS_DIR}/deploy_runner.py" "${OS_TYPE}" "${HOST_IP}" "${HOST_PORT}" "${HOST_USER}" "${HOST_PASS}" "${WAZUH_MANAGER_IP}" "${WAZUH_AGENT_VERSION}"; then
        DEPLOY_SUCCESS=1
    fi
fi

# 5. Kết luận và cập nhật trạng thái vào servers.md
if [ "${DEPLOY_SUCCESS}" -eq 1 ]; then
    echo -e "\n${BOLD}${GREEN}============================================================${NC}"
    echo -e "${BOLD}${GREEN}[THÀNH CÔNG] ĐÃ CÀI ĐẶT VÀ KHỞI ĐỘNG WAZUH AGENT TRÊN ${HOST_NAME}!${NC}"
    echo -e "${BOLD}${GREEN}============================================================${NC}"

    TODAY="$(date +'%Y-%m-%d %H:%M')"
    # Cập nhật trạng thái trong servers.md
    if [ -f "${SERVERS_MD}" ]; then
        sed -i -E "s/(\| \`${HOST_NAME}\` \| .*? \| )[^|]+( \| [^|]+ \|)$/\1✅ Đã cài đặt (Hoạt động)\2/g" "${SERVERS_MD}" || true
    fi
    exit 0
else
    echo -e "\n${BOLD}${RED}============================================================${NC}"
    echo -e "${BOLD}${RED}[THẤT BẠI] Triển khai Wazuh Agent không thành công trên ${HOST_NAME}!${NC}"
    echo -e "${BOLD}${RED}============================================================${NC}"
    exit 1
fi
