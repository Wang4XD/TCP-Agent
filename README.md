# TCP-Agent

Interact with TCP application (StairPlex) through natural language.


Developed an Agent to interact with high-throughput neural signal acquisition software (StairPlex) using GPT-4o and custom cue word engineering, and implemented an adaptive binary data parsing algorithm using the struct module, solving the problem of only being able to interact with StairPlex via the TCP command line or the QT front-end. 

## Acknowledgement

Shanghai Stairmed Technology Co., Ltd


## Usage

1. ``` pip install -r requirements.txt ```

2. Test for connectivity to the application ``` python test_tcp_conn.py ```

3. Running Agent ``` python tcp_agent.py ```
