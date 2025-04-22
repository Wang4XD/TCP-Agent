import streamlit as st
import socket
import time
import json
import re
import os
import struct
from openai import OpenAI
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import threading
import queue
import binascii

# 设置页面配置
st.set_page_config(
    page_title="TCP Agent - TCP通信控制系统",
    page_icon="🤖",
    layout="wide",
)

# 系统常量
TCP_HOST = '127.0.0.1'
TCP_PORT = 7000
MAX_CHANNELS = 128
THRESHOLD_RANGE = (-100, 100)

# 初始化session state
if 'connection_status' not in st.session_state:
    st.session_state.connection_status = False
if 'conversation' not in st.session_state:
    st.session_state.conversation = []
if 'channel_values' not in st.session_state:
    st.session_state.channel_values = {}
if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False
if 'stop_monitoring' not in st.session_state:
    st.session_state.stop_monitoring = threading.Event()
if 'message_queue' not in st.session_state:
    st.session_state.message_queue = queue.Queue()


# 加载OpenAI API密钥
def load_api_key():
    if 'OPENAI_API_KEY' in os.environ:
        return os.environ['OPENAI_API_KEY']

    if 'openai_api_key' in st.session_state:
        return st.session_state.openai_api_key

    return None


# 设置OpenAI客户端
def get_openai_client():
    api_key = load_api_key()
    if api_key:
        return OpenAI(api_key=api_key)
    return None


# 二进制数据解析函数
def parse_binary_data(binary_data):
    """
    解析二进制数据返回通道值
    """
    try:
        # 尝试从二进制数据中提取通道值
        # 这里使用示例解析逻辑，需要根据实际二进制格式进行调整
        result = {}

        # 检查数据长度是否足够
        if len(binary_data) < 4:  # 假设至少需要4字节头部
            return {}

        # 解析头部信息，假设前4字节是头部
        header = struct.unpack('>I', binary_data[:4])[0]

        # 跳过头部，处理数据部分
        data_start = 4

        # 假设每个通道的数据是一个浮点数（4字节）
        bytes_per_channel = 4
        max_channels = min(MAX_CHANNELS, (len(binary_data) - data_start) // bytes_per_channel)

        for i in range(max_channels):
            offset = data_start + i * bytes_per_channel

            # 确保有足够的数据可以读取
            if offset + bytes_per_channel <= len(binary_data):
                # 解析为浮点数
                try:
                    value = struct.unpack('>f', binary_data[offset:offset + bytes_per_channel])[0]
                    channel = i + 1  # 通道从1开始
                    result[channel] = value
                except struct.error:
                    pass

        return result
    except Exception as e:
        st.error(f"二进制数据解析错误: {str(e)}")
        return {}


# TCP客户端函数 - 修改处理二进制响应
def send_tcp_command(command, expect_response=True):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(5)  # 设置超时时间为5秒
        client_socket.connect((TCP_HOST, TCP_PORT))

        # 发送命令
        client_socket.sendall(command.encode('utf-8'))

        response_data = b""
        if expect_response:
            # 接收二进制响应
            chunks = []
            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except socket.timeout:
                    break

            response_data = b''.join(chunks)

        return True, response_data
    except socket.error as e:
        return False, f"TCP通信错误: {e}"
    finally:
        client_socket.close()


# 检查TCP连接
def check_connection():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(2)  # 设置超时时间
        result = client_socket.connect_ex((TCP_HOST, TCP_PORT))
        client_socket.close()
        return result == 0
    except:
        return False


# 处理搜索结果
def handle_search_results(binary_response, command):
    """处理搜索命令的二进制响应"""
    # 根据命令解析出请求的通道
    requested_channels = []
    if "channel all" in command:
        requested_channels = list(range(1, MAX_CHANNELS + 1))
    else:
        # 提取指定的通道号
        matches = re.findall(r"channel\s+([0-9\s]+)", command)
        if matches:
            channel_str = matches[0].strip()
            requested_channels = [int(ch) for ch in channel_str.split() if ch.isdigit()]

    # 解析二进制数据
    channel_values = parse_binary_data(binary_response)

    # 过滤出请求的通道
    if requested_channels:
        channel_values = {ch: val for ch, val in channel_values.items() if ch in requested_channels}

    # 更新全局状态
    for channel, value in channel_values.items():
        st.session_state.channel_values[channel] = value

    return channel_values


# 获取通道值的可读表示
def get_readable_channel_values(channel_values):
    """将通道值转换为可读的字符串表示"""
    if not channel_values:
        return "未获取到通道数据"

    result = []
    for channel, value in sorted(channel_values.items()):
        result.append(f"Channel {channel}: {value:.2f}")

    return "\n".join(result)


# GPT代理系统提示
SYSTEM_PROMPT = """你是一个专业的TCP通信控制系统代理。你可以帮助用户控制一个只能通过TCP协议访问的软件。

操作流程必须严格遵循:
1. 设置阈值: set SPK threshold channel [通道号] value [阈值]
   - 通道号: 1到128
   - 阈值范围: -100到100
   - 例如: set SPK threshold channel 1 value -50
   - 可以一次设置多个通道: set SPK threshold channel 5 6 value -30 40

2. 启动系统: start ACQ

3. 查询分析: 
   - 查询所有通道: search VOL channel all
   - 查询指定通道: search VOL channel 1 2 (查询通道1和2)

4. 关闭系统: stop ACQ

请始终按照这个流程帮助用户执行操作。如果用户想执行查询而系统未启动，请先建议启动系统。如果用户想要退出，请确保系统已停止。

回复格式要求:
1. 仅提供有效的TCP命令，不要添加任何注释。
2. 如果用户请求需要多条命令完成，请用分号(;)分隔各命令。
3. 如果用户请求复杂或模糊，请在命令前添加简短说明，然后提供命令。
4. 针对设置阈值的请求，确保通道号在1-128范围内，阈值在-100到100范围内。

你的回复将直接发送到TCP服务器执行，请保持精确。
"""


# 使用GPT进行自然语言处理
def process_with_gpt(user_message):
    client = get_openai_client()
    if not client:
        return "请先设置OpenAI API密钥"

    # 构建对话历史
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    # 添加最近的对话历史 (最多3轮)
    recent_history = st.session_state.conversation[-6:] if len(st.session_state.conversation) > 0 else []
    for msg in recent_history:
        messages.append({"role": msg["role"], "content": msg["content"]})

    # 添加当前用户消息
    messages.append({"role": "user", "content": user_message})

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            temperature=0.3,
            max_tokens=500
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"调用GPT时出错: {str(e)}"


# 解析GPT响应生成TCP命令
def parse_gpt_response(response):
    # 检查是否包含TCP命令
    commands = []

    # 查找分号分隔的多个命令
    if ';' in response:
        # 分割基于分号的多条命令
        raw_commands = response.split(';')
        for cmd in raw_commands:
            cmd = cmd.strip()
            if cmd and is_valid_command(cmd):
                commands.append(cmd)
    else:
        # 分析文本找出命令部分
        lines = response.split('\n')
        for line in lines:
            line = line.strip()
            # 检查是否是有效命令
            if is_valid_command(line):
                commands.append(line)

    # 如果没有找到有效命令，尝试从整个响应中提取
    if not commands:
        # 提取引号中的内容作为可能的命令
        quoted_matches = re.findall(r'"([^"]*)"', response) + re.findall(r"'([^']*)'", response)
        for match in quoted_matches:
            if is_valid_command(match):
                commands.append(match)

    # 如果仍未找到，尝试检查整个响应是否是命令
    if not commands and is_valid_command(response):
        commands.append(response)

    return commands


# 检查是否是有效命令
def is_valid_command(text):
    valid_prefixes = [
        "set SPK threshold channel",
        "start ACQ",
        "stop ACQ",
        "search VOL channel"
    ]

    text = text.strip()
    return any(text.startswith(prefix) for prefix in valid_prefixes)


# 执行命令
def execute_commands(commands):
    results = []
    for cmd in commands:
        success, response = send_tcp_command(cmd)

        # 处理查询命令的结果
        readable_response = ""
        if success:
            if cmd.startswith("search VOL channel"):
                channel_values = handle_search_results(response, cmd)
                readable_response = get_readable_channel_values(channel_values)
            elif isinstance(response, bytes):
                # 如果不是搜索命令但返回的是二进制数据，提供十六进制表示
                readable_response = f"二进制响应: {len(response)} 字节"
                if len(response) > 0:
                    try:
                        # 尝试解码为ASCII
                        ascii_response = response.decode('ascii', errors='replace')
                        if any(c.isalnum() for c in ascii_response):
                            readable_response += f"\nASCII: {ascii_response[:100]}..."
                    except:
                        pass
            else:
                readable_response = str(response)
        else:
            readable_response = response

        results.append({
            "command": cmd,
            "success": success,
            "response": readable_response,
            "raw_response": response
        })

    return results


# 监控函数
def monitoring_task():
    while not st.session_state.stop_monitoring.is_set():
        try:
            success, response = send_tcp_command("search VOL channel all")
            if success:
                channel_data = handle_search_results(response, "search VOL channel all")
                st.session_state.message_queue.put({"type": "channel_update", "data": channel_data})
            time.sleep(1)  # 每秒更新一次
        except Exception as e:
            st.session_state.message_queue.put({"type": "error", "data": str(e)})
            break


# 开始监控
def start_monitoring():
    if not st.session_state.monitoring:
        st.session_state.stop_monitoring.clear()
        st.session_state.monitoring = True
        executor = ThreadPoolExecutor(max_workers=1)
        executor.submit(monitoring_task)


# 停止监控
def stop_monitoring():
    if st.session_state.monitoring:
        st.session_state.stop_monitoring.set()
        st.session_state.monitoring = False


# 自动启动命令序列
def auto_start_sequence():
    commands = ["stop ACQ", "start ACQ"]
    results = []
    for cmd in commands:
        success, response = send_tcp_command(cmd)
        readable_response = ""
        if isinstance(response, bytes):
            readable_response = f"二进制响应: {len(response)} 字节"
        else:
            readable_response = str(response)

        results.append({
            "command": cmd,
            "success": success,
            "response": readable_response
        })
        time.sleep(0.5)  # 等待命令执行
    return results


# 自动关闭命令序列
def auto_stop_sequence():
    stop_monitoring()
    success, response = send_tcp_command("stop ACQ")
    readable_response = ""
    if isinstance(response, bytes):
        readable_response = f"二进制响应: {len(response)} 字节"
    else:
        readable_response = str(response)

    return [{
        "command": "stop ACQ",
        "success": success,
        "response": readable_response
    }]


# 可视化通道数据
def visualize_channel_data(channels=None):
    if not st.session_state.channel_values:
        return None

    # 过滤所需通道
    data = st.session_state.channel_values
    if channels:
        data = {ch: val for ch, val in data.items() if ch in channels}

    # 创建数据框
    df = pd.DataFrame({
        '通道': list(data.keys()),
        '值': list(data.values())
    })

    # 创建柱状图
    fig = make_subplots(specs=[[{"secondary_y": True}]])

    fig.add_trace(
        go.Bar(
            x=df['通道'],
            y=df['值'],
            name='通道值',
            marker_color='royalblue'
        )
    )

    fig.update_layout(
        title='通道值可视化',
        xaxis_title='通道',
        yaxis_title='值',
        height=400,
        margin=dict(l=20, r=20, t=50, b=20),
    )

    return fig


# 显示二进制数据调试信息
def show_binary_debug_info(binary_data):
    if not binary_data:
        return "无数据"

    try:
        # 显示前100个字节的十六进制
        hex_dump = binascii.hexlify(binary_data[:100]).decode('ascii')
        hex_formatted = ' '.join(hex_dump[i:i + 2] for i in range(0, len(hex_dump), 2))

        result = f"数据长度: {len(binary_data)} 字节\n"
        result += f"十六进制前缀: {hex_formatted}"

        # 尝试ASCII解码
        try:
            ascii_text = binary_data[:100].decode('ascii', errors='replace')
            printable_chars = ''.join(c if c.isprintable() or c in ' \t\n\r' else '.' for c in ascii_text)
            result += f"\nASCII预览: {printable_chars}"
        except:
            pass

        return result
    except Exception as e:
        return f"解析错误: {str(e)}"


# UI布局
def render_ui():
    st.title("🤖 SPK Agent - TCP通信控制系统")

    # 侧边栏设置
    with st.sidebar:
        st.header("设置")

        # API密钥设置
        api_key = st.text_input("OpenAI API密钥", type="password", value=load_api_key() or "")
        if api_key:
            st.session_state.openai_api_key = api_key

        # TCP连接状态
        connection_status = check_connection()
        st.session_state.connection_status = connection_status

        st.write("TCP连接状态: " +
                 ("✅ 已连接" if connection_status else "❌ 未连接"))

        # 系统控制按钮
        col1, col2 = st.columns(2)
        with col1:
            start_button = st.button("启动系统", type="primary", disabled=not connection_status)
        with col2:
            stop_button = st.button("停止系统", type="primary", disabled=not connection_status)

        if start_button:
            results = auto_start_sequence()
            for result in results:
                if result["success"]:
                    st.success(f"执行成功: {result['command']}")
                else:
                    st.error(f"执行失败: {result['command']} - {result['response']}")
            start_monitoring()

        if stop_button:
            results = auto_stop_sequence()
            for result in results:
                if result["success"]:
                    st.success(f"执行成功: {result['command']}")
                else:
                    st.error(f"执行失败: {result['command']} - {result['response']}")

        # 通道阈值快速设置
        st.subheader("通道阈值快速设置")
        with st.form("threshold_form"):
            col1, col2 = st.columns(2)
            with col1:
                channel_input = st.text_input("通道号",
                                              help="输入通道号(1-128)，多个通道用空格分隔")
            with col2:
                threshold_value = st.slider("阈值",
                                            min_value=THRESHOLD_RANGE[0],
                                            max_value=THRESHOLD_RANGE[1],
                                            value=0)

            submit_button = st.form_submit_button("设置阈值", disabled=not connection_status)

            if submit_button:
                try:
                    # 验证通道输入
                    channels = [int(ch) for ch in channel_input.split()]
                    if any(ch < 1 or ch > MAX_CHANNELS for ch in channels):
                        st.error(f"通道号必须在1-{MAX_CHANNELS}范围内")
                    else:
                        # 构建命令
                        channels_str = " ".join(str(ch) for ch in channels)
                        values_str = " ".join([str(threshold_value)] * len(channels))
                        command = f"set SPK threshold channel {channels_str} value {values_str}"

                        # 执行命令
                        success, response = send_tcp_command(command)
                        readable_response = "二进制响应" if isinstance(response, bytes) else str(response)
                        if success:
                            st.success(f"阈值设置成功: {command}")
                        else:
                            st.error(f"阈值设置失败: {readable_response}")
                except ValueError:
                    st.error("请输入有效的通道号")

        # 二进制数据格式配置
        st.subheader("二进制数据格式")

        with st.expander("高级设置"):
            st.markdown("""
            如果你知道二进制数据的确切格式，可以在此处配置解析方法。
            目前使用的是通用解析方法，可能需要根据实际二进制格式调整。
            """)

            st.code("""
            # 当前解析逻辑假设:
            # - 头部4字节
            # - 每个通道值为4字节浮点数
            # - 大端字节序
            """)

    # 主界面
    tabs = st.tabs(["命令控制", "数据可视化", "数据调试", "帮助"])

    # 命令控制选项卡
    with tabs[0]:
        # 对话历史
        st.subheader("与Agent对话")
        for msg in st.session_state.conversation:
            if msg["role"] == "user":
                st.chat_message("user").write(msg["content"])
            else:
                st.chat_message("assistant").write(msg["content"])

        # 用户输入
        user_input = st.chat_input("输入指令...", disabled=not connection_status or not load_api_key())

        if user_input:
            # 显示用户输入
            st.chat_message("user").write(user_input)

            # 保存对话
            st.session_state.conversation.append({"role": "user", "content": user_input})

            # 处理用户输入
            gpt_response = process_with_gpt(user_input)

            # 解析GPT响应
            commands = parse_gpt_response(gpt_response)

            # 显示GPT响应
            st.chat_message("assistant").write(gpt_response)

            # 保存对话
            st.session_state.conversation.append({"role": "assistant", "content": gpt_response})

            # 如果找到命令，执行它们
            if commands:
                with st.status("执行TCP命令..."):
                    results = execute_commands(commands)
                    for result in results:
                        if result["success"]:
                            st.write(f"✅ 执行成功: {result['command']}")
                            if "search VOL" in result["command"]:
                                st.write(f"📊 结果: {result['response']}")
                        else:
                            st.write(f"❌ 执行失败: {result['command']} - {result['response']}")
            else:
                st.warning("未找到有效的TCP命令")

    # 数据可视化选项卡
    with tabs[1]:
        col1, col2 = st.columns([3, 1])

        with col1:
            st.subheader("通道数据可视化")

            # 如果有通道数据，显示可视化图表
            if st.session_state.channel_values:
                # 创建图表
                fig = visualize_channel_data()
                if fig:
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("尚无通道数据。请使用search VOL命令查询数据。")

        with col2:
            st.subheader("数据监控")
            monitor_toggle = st.toggle("实时监控", value=st.session_state.monitoring, disabled=not connection_status)

            if monitor_toggle != st.session_state.monitoring:
                if monitor_toggle:
                    start_monitoring()
                else:
                    stop_monitoring()

            # 显示通道数据表格
            if st.session_state.channel_values:
                data = st.session_state.channel_values
                df = pd.DataFrame({
                    '通道': list(data.keys()),
                    '值': list(data.values())
                })
                df = df.sort_values('通道')
                st.dataframe(df, use_container_width=True, height=300)

    # 数据调试选项卡
    with tabs[2]:
        st.subheader("二进制数据调试")

        st.markdown("""
        此页面用于调试二进制数据解析。您可以发送查询命令并查看原始二进制响应。
        """)

        col1, col2 = st.columns(2)

        with col1:
            debug_command = st.text_input("测试命令", value="search VOL channel all")
            debug_button = st.button("发送", disabled=not connection_status)

        if debug_button and debug_command:
            success, raw_response = send_tcp_command(debug_command)

            if success:
                st.success("命令发送成功")

                # 显示二进制数据信息
                st.subheader("原始二进制数据")
                st.text(show_binary_debug_info(raw_response))

                # 如果是查询命令，显示解析结果
                if debug_command.startswith("search VOL channel"):
                    st.subheader("解析结果")
                    channel_values = handle_search_results(raw_response, debug_command)

                    if channel_values:
                        # 创建数据框
                        df = pd.DataFrame({
                            '通道': list(channel_values.keys()),
                            '值': list(channel_values.values())
                        })
                        df = df.sort_values('通道')
                        st.dataframe(df)
                    else:
                        st.warning("未能从二进制数据中解析出通道值")
            else:
                st.error(f"命令执行失败: {raw_response}")

    # 帮助选项卡
    with tabs[3]:
        st.subheader("使用指南")

        st.markdown("""
        ### 系统操作流程

        必须按照以下顺序操作系统:

        1. **设置阈值**
            - 命令格式: `set SPK threshold channel [通道号] value [阈值]`
            - 通道范围: 1-128
            - 阈值范围: -100到100
            - 示例: `set SPK threshold channel 1 value -50`
            - 可一次设置多个通道: `set SPK threshold channel 5 6 value -30 40`

        2. **启动系统**
            - 命令: `start ACQ`
            - 可以使用界面右侧的"启动系统"按钮

        3. **查询分析**
            - 查询所有通道: `search VOL channel all`
            - 查询特定通道: `search VOL channel 1 2`（查询通道1和2）

        4. **关闭系统**
            - 命令: `stop ACQ`
            - 可以使用界面右侧的"停止系统"按钮

        ### 自然语言控制

        您可以使用自然语言与系统交互，例如:

        - "帮我设置通道5的阈值为30"
        - "查询所有通道的数据"
        - "启动系统"
        - "停止系统"
        - "设置通道1到5的阈值都为-40"

        ### 实时监控

        在"数据可视化"选项卡中，您可以:

        - 开启实时监控自动查询所有通道数据
        - 查看通道数据的图形展示
        - 查看通道数据表格

        ### 二进制数据调试

        如果二进制数据解析出现问题，可以在"数据调试"选项卡中:

        - 发送测试命令查看原始二进制响应
        - 查看解析后的数据
        - 提供信息给开发人员调整解析算法
        """)


# 检查消息队列并更新界面
def check_message_queue():
    while not st.session_state.message_queue.empty():
        message = st.session_state.message_queue.get()

        if message["type"] == "channel_update":
            # 更新通道数据
            st.session_state.channel_values.update(message["data"])
            st.rerun()
        elif message["type"] == "error":
            # 处理错误
            st.error(f"监控错误: {message['data']}")
            stop_monitoring()
            st.rerun()


# 主函数
def main():
    render_ui()
    check_message_queue()


if __name__ == "__main__":
    main()