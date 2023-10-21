# netflow2json

This is a Python-based solution for collecting and analyzing Netflow V9 traffic data.

## Installation

You can install `netflow2json` using pip:

```bash
pip install netflow2json
```

## Usage

To use `netflow2json`, you can create an instance of the `NetflowProcessor` class and start processing Netflow data. See the [Examples](#examples) section for detailed usage examples.


## Configuration

You can configure the package by specifying the `web_port`, `netflow_port`, and `local_ip_ranges` when creating a `NetflowProcessor` instance.


- **`local_ip_ranges`**: This section is used to define local IP address ranges. The code uses these ranges to categorize Netflow traffic as "Local," "Upload," or "Download."

  Example:

  ```ini
  local_ip_ranges = ["192.168.0.0/24", "172.16.11.0/24", "172.16.12.0/24", "172.16.13.0/24", "172.16.14.0/24", "172.16.16.0/24"]
  ```

- **`netflow_port`**: Specify the port (UDP) on which the code listens for incoming Netflow v9 traffic.

  Example:

  ```ini
  netflow_port = 2055
  ```

- **`web_port`**: Specify the port of web accessible json results.

 ```ini
  web_port = 80
  ```


### Examples

```python
from netflow2json.analyser import NetflowProcessor

processor = NetflowProcessor(web_port=8080, netflow_port=2055, local_ip_ranges=['172.16.11.0/24','172.16.12.0/24','172.16.13.0/24','172.16.14.0/24','192.168.0.0/24','192.168.1.0/24'])
processor.start()
```

## License

This project is licensed under the MIT License

## Project Repository

Visit the [GitHub repository](https://github.com/h-haghpanah/netflow2json) for the latest updates and to contribute.

## Bug Tracker

If you encounter any issues or want to report a bug, please visit the [Bug Tracker](https://github.com/h-haghpanah/netflow2json/issues).

## Contact Information

For questions or support, you can reach out to the author at h.haghpanah@outlook.com.

