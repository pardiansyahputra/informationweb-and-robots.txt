# Website Information Analysis and Robots.txt Checker GUI Application

This application is a Tkinter-based graphical user interface (GUI) that allows you to retrieve basic information from a website or IP address, as well as check the contents of the `robots.txt` file on that website.

## Key Features

* **Website Information:**
    * Obtains the IP address from a URL or accepts direct IP address input.
    * Attempts to retrieve the hostname from the IP address.
    * Retrieves detailed website information, including:
        * Final URL after redirects.
        * HTTP status code.
        * Server information.
        * Date.
        * Content type.
        * Encoding.
        * Response time.
        * Content size.
        * Cookies.
        * Redirect history (if any).
        * HTTP security headers (Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
* **Robots.txt Checker:**
    * Retrieves and displays the content of the `robots.txt` file from a given URL.
    * Handles cases where the `robots.txt` file is not found.
* **Intuitive User Interface:**
    * Feature selection via a dropdown menu.
    * Target input (URL or IP) through a text field.
    * Structured and easy-to-read results display with color-coding for important information and errors.
    * Button to clear previous results.
* **Non-Blocking Operation:** Website information and `robots.txt` retrieval are performed in separate threads, preventing the GUI from freezing during the process.
* **Color Configuration:** Customizable theme colors for a more appealing look.
