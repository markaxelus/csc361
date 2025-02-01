## Description

This script is a simple web tester that connects to a given URL, retrieves HTTP headers, checks for HTTP/2 support, extracts cookies, follows redirects, and determines if the page is password-protected.

## How to Run

Run the script with the following command:

```
python3 SmartClient.py <URL>
```

Replace <URL> with the actual website you want to test.

### Example:

```
python3 WebTester.py www.uvic.ca
```

If an incorrect URL format is provided, the script will exit with an error message.

### Output Information

The script prints the following information:

* Website host

1. HTTP/2 support status

2. List of cookies extracted (if any)

3. Password-protected status (if applicable)
