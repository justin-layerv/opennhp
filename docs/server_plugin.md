---
layout: page
title: Server Plugins
nav_order: 9
permalink: /server_plugin/
---

# OpenNHP Plugin Development Guide
{: .fs-9 }

[中文版](/zh-cn/server_plugin/){: .label .fs-4 }

---

## Table of Contents

- [Introduction](#introduction)

- [1. The Necessity of Applying OpenNHP Plugins](#1-the-necessity-of-applying-opennhp-plugins)

    - [1.1 Protocol Compatibility and Technical Limitations](#11-protocol-compatibility-and-technical-limitations)

    - [1.2 Customization Needs for Authentication](#12-customization-needs-for-authentication)

- [2. How the Plugin Works](#2-how-the-plugin-works)

    - [2.1 User Initiates an HTTP Request via Browser](#21-user-initiates-an-http-request-via-browser)

    - [2.2 NHP Server Parses the URL and Calls the Appropriate Plugin](#22-nhp-server-parses-the-url-and-calls-the-appropriate-plugin)

    - [2.3 The Plugin Executes Core Functionality](#23-the-plugin-executes-core-functionality)

    - [2.4 Plugin Completes the Code Execution Process](#24-plugin-completes-the-code-execution-process)

    - [2.5 NHP Server Responds to the User with the HTTP Request Results](#25-nhp-server-responds-to-the-user-with-the-http-request-results)

- [3. Plugin Development Principles](#3-plugin-development-principles)

    - [3.1 Environment Setup](#31-environment-setup)

    - [3.2 Project Initialization](#32-project-initialization)

    - [3.3 Plugin Function Design](#33-plugin-function-design)

    - [3.4 Core Code Development](#34-core-code-development)

    - [3.5 Plugin Compilation, Testing, and Deployment](#35-plugin-compilation-testing-and-deployment)

- [Conclusion](#conclusion)

## Introduction

Plugins in the NHP server are modules that add specific features to the main application. They are designed to be highly modular and loosely coupled with the core application, allowing developers to add, remove, or update plugins without affecting the main functionality of the server.

## 1. The Necessity of Applying OpenNHP Plugins

The development of OpenNHP plugins solves the compatibility issues between the UDP protocol and web-based HTTP requests, while also addressing the customization needs for authentication in government platforms. Developing plugins is crucial for further extending the NHP framework and adapting it to the flexible needs of government data flow applications. The reasons are as follows:

### 1.1 Protocol Compatibility and Technical Limitations

The NHP standard protocol communicates over the UDP protocol, which is lightweight and fast, making it suitable for large-scale, high-frequency data transmissions. However, in certain scenarios, especially web-based interactions (e.g., HTML5 web pages), JavaScript running in a browser can only make HTTP requests and cannot directly send UDP requests. This creates a protocol incompatibility issue. Many modern government applications rely on web interactions, making plugin development essential to overcome this technical limitation.

By developing OpenNHP plugins, the NHP server can receive HTTP requests from web clients (often "knock packets") and convert them into the UDP protocol needed for internal communication. This mechanism ensures seamless integration between web applications based on HTTP and the NHP server, extending the NHP framework's application scope. It particularly enhances flexibility and compatibility in data transmission in scenarios involving browser-to-backend service interactions.

### 1.2 Customization Needs for Authentication

Government data flow involves highly secure identity authentication and access management. However, standard authentication protocols cannot meet the complex needs of government scenarios. Different government platforms have their own authentication mechanisms and demand highly customized authentication processes. Traditional standard protocols are too rigid to flexibly integrate with these platforms.

OpenNHP plugins can interface with different government platforms by offering custom services to accommodate their authentication processes. The plugins allow developers to tailor the authentication mechanisms according to the specific requirements of different platforms, ensuring seamless integration with the NHP framework. This not only enhances authentication security but also ensures compliance and flexibility in data flow management.

## 2. How the Plugin Works

The entire plugin execution process covers the complete flow from user requests, server plugin parsing, plugin logic execution, to final feedback to the user. Each step ensures that the NHP server, via the plugin, meets the demands of various request processing scenarios, especially in authentication and "knock packet" handling.

![Plugin Workflow Diagram](/images/plugin_image2.png)

***Figure 1: Plugin Workflow Diagram***

### 2.1 User Initiates an HTTP Request via Browser

The user inputs a specific URL address in their browser, sending an HTTP request to the NHP server. For example, a user accesses the following URL:
- `http://127.0.0.1:port/plugins/example?resid=demo&action=login`

This is the starting point of the entire process, typically initiated by a webpage or application request that needs to be handled by the plugin.

| URL Component    | Description                                                 |
| ---------------- | ------------------------------------------------------------|
| `127.0.0.1:port` | The first part is the IP address of the NHP server, followed by the port number |
| `plugins`        | Plugin directory                                             |
| `example`        | Plugin name                                                  |
| `resid`          | Plugin resource ID                                           |
| `action`         | The action to be executed, used to determine which auxiliary function the plugin performs |

***Table 1: URL Component Breakdown***

### 2.2 NHP Server Parses the URL and Calls the Appropriate Plugin

After the HTTP request reaches the NHP server, the server parses the URL path and parameters to determine which plugin to call. During this process, the NHP server identifies the `plugins/example` part of the URL and routes the request to the "example" plugin for processing.

### 2.3 The Plugin Executes Core Functionality

Based on the parameters in the URL (such as `resid=demo` and `action=login`), the plugin executes the corresponding functionality. The core functions of the plugin include authentication and a series of "knock packet" processing steps. The core functionality handles the main logic, while auxiliary functions provide support for tasks such as authentication and resource access.

### 2.4 Plugin Completes the Code Execution Process

After processing the request and completing the authentication or other custom services, the plugin finishes its code execution process. This step is key to the core functionality of the plugin, where all authentication, authorization, or other logic is executed.

### 2.5 NHP Server Responds to the User with the HTTP Request Results

Once the plugin finishes its process, the result is sent back to the NHP server, which responds to the user via HTTP. The user will eventually see a feedback message in their browser, such as a confirmation message or relevant data or page update.

## 3. Plugin Development Principles

### 3.1 Environment Setup

Before developing OpenNHP plugins, ensure the following environment is properly set up:

1. **Development Language**: Go language is used for development.
2. **Development Tools**: IDEs like IntelliJ IDEA or VS Code are recommended.
3. **OpenNHP source code**: Download and integrate the latest version of the OpenNHP code from GitHub into your development environment. Download URL: [https://github.com/OpenNHP/opennhp](https://github.com/OpenNHP/opennhp).

### 3.2 Project Initialization

First, create a new plugin project under the `server/plugins` directory. For example, let's create a plugin named "example."

![Example Plugin Directory Structure](/images/plugin_image3.png)

***Figure 2: Example Plugin Parent Directory***

Each plugin in the NHP server is typically structured as a separate Go package. For instance, the "example" plugin would be located in the `NHP/server/plugins/example` directory and would have its own `example.go` file.

The initialized project structure includes basic configuration files and the plugin framework, primarily consisting of the `etc` directory with configuration files (`config.toml`, `resource.toml`), the main program file `main.go`, and the automation build file `Makefile`. If the plugin requires integration with front-end pages, the `templates` directory and corresponding front-end HTML files can also be added.

A typical plugin file, such as `example.go`, contains the following:

- Necessary import statements
- Constants and variables related to the plugin
- Helper functions
- Main plugin function

![Example Plugin Directory Structure](/images/plugin_image4.png)

***Figure 3: Example Plugin Directory Structure***

| ***File/Directory Name*** | ***Purpose***                                              |
| ------------------------- | ---------------------------------------------------------- |
| etc                       | Contains configuration and resource files for the plugin    |
| config.toml               | Defines configuration details for the plugin during runtime |
| resource.toml             | Defines resource-related information for the plugin         |
| templates                 | Stores integrated front-end page templates (optional)       |
| main.go                   | Main program file defining core functions and helper logic  |
| Makefile                  | Automation build file                                      |

***Table 2: Plugin Directory and File Purposes***

## 3.3 Plugin Function Design

In the plugin function design phase, the following core points need to be clarified:

***Data Flow Scenarios***: Define the participants, permissions, and flow paths involved in the data circulation process.

***Security Policies***: Establish strict access control and verification mechanisms through a zero-trust architecture.

***Logging and Auditing***: Design comprehensive logging functionalities for subsequent tracing and auditing.

For example, the main functionality to be implemented by the "example" plugin is as follows:

1. Submit a form containing user name and password on the H5 page;

2. The NHP-Server server receives the form for verification. After the verification is successful, it initiates a knock on the NHP-AC server;

3. After NHP-AC successfully opens the door, it returns the application server address to the client;

4. Access application server resources.

## 3.4 Core Code Development

The steps for developing the plugin for the NHP server are as follows:

1. Create a new directory for your plugin under `endpoints/server/plugins/`. The directory name should be the name of your plugin.

2. In the plugin directory, create a new Go file. The file name should be the same as the directory name. For example, for a plugin named myplugin, you would create a file named myplugin.go.

3. Implement the `PluginHandler` interface which requires an `AuthWithHttp` method.

4. Register your plugin in an `init()` function:
   ```go
   func init() {
       plugins.RegisterPlugin("myplugin", New)
   }
   ```

5. Import your plugin in the main application with a blank import. In `endpoints/server/main/main.go`, add:
   ```go
   import (
       _ "github.com/OpenNHP/opennhp/endpoints/server/plugins/myplugin"
   )
   ```

Refer to the plug-in function design for code development. Taking the "example" plug-in as an example, the AuthWithHttp function is designed to receive and process HTTP requests, the authRegular function verifies the user name and password and knocks on the door, the authAndShowLogin function loads login page resources, etc., and verification auxiliary functions need to be designed to implement the functions. Expansion and development can be carried out according to specific functional requirements.

![Example Plugin Core Code and Auxiliary Code Function Example](/images/plugin_image6.png) 

![Example Plugin Core Code and Auxiliary Code Function Example](/images/plugin_image7.png) 

![Example Plugin Core Code and Auxiliary Code Function Example](/images/plugin_image8.png) 

***Figures 4, 5, 6 Example Plugin Core Code and Auxiliary Code Function Example***

## 3.5 Plugin Compilation Testing and Deployment

Testing and deployment of the plugin are crucial steps to ensure the completeness and stability of plugin functionality. Through local environment testing and optimization, developers can deploy the plugin in a way that ensures the correctness of its functionality.

**1. Plugin Compilation**

NHP Server plugins are **statically compiled** into the server binary. This means there are no separate `.so` plugin files—plugins are part of the main server executable.

**Plugin Registration Pattern:**

Each plugin uses Go's `init()` function to register itself with a central plugin registry:

```go
package myplugin

import "github.com/OpenNHP/opennhp/endpoints/server/plugins"

const PluginID = "myplugin"

func init() {
    plugins.RegisterPlugin(PluginID, New)
}

func New(params map[string]string) plugins.PluginHandler {
    return &MyPlugin{...}
}
```

**Blank Imports:**

The server's `main.go` imports plugins using blank imports to trigger their `init()` functions:

```go
import (
    _ "github.com/OpenNHP/opennhp/endpoints/server/plugins/passcode"
    _ "github.com/OpenNHP/opennhp/endpoints/server/plugins/oidc"
    _ "github.com/OpenNHP/opennhp/endpoints/server/plugins/myplugin"  // Add your plugin
)
```

**Build Process:**

Simply build the server with `make serverd` or `CGO_ENABLED=0 go build`. Your plugin code is compiled directly into the server binary—no separate plugin compilation step needed.

**2. Local Environment Function Testing**

To test your plugin, you can write a separate _test.go file in the same directory as the plugin file to write unit tests. Go's built-in testing package (testing) can be used to write and run tests.

Once the plugin development is complete and compiled successfully, it is necessary to perform functional testing in the local environment first. This step is primarily used to verify whether the core functionality of the plugin has been correctly implemented and to ensure that all functional modules of the plugin are working correctly. You can simulate actual application scenario requests to verify whether the plugin's response meets expectations and check the logs for potential issues. Common testing steps include:

1. Initiate HTTP or UDP requests to test the plugin's response;

2. Verify whether the identity authentication, knocking, opening, and authorization processes in the plugin are executed as expected;

3. Test the plugin's error handling and exception capture mechanisms;

During the local testing phase, developers can use debugging tools, logging, and breakpoint debugging to thoroughly investigate and resolve potential issues in the code, ensuring the logic of the plugin is rigorous and free of major vulnerabilities.

**3. Function Confirmation and Optimization**

After local environment testing passes, developers need to confirm and optimize the plugin's functionality. Confirm whether the core functions of the plugin fully meet the description in the requirements document, and whether all expected functionalities have been correctly implemented. If certain functions of the plugin are found to be below expectations or have further optimization potential during testing, code adjustments and functionality optimizations can be made based on the test results.

**4. Configuration and Deployment in Actual Application Scenarios**

Once local testing and optimization are complete, the plugin can proceed to the deployment phase. Since plugins are statically compiled into the server binary, deployment is straightforward:

***Build and Deploy***:
1. Add your plugin's blank import to `endpoints/server/main/main.go`
2. Build the server: `make serverd` or `CGO_ENABLED=0 go build`
3. Deploy the new server binary (Docker image or native binary)

***Terraform Configuration***:
Add your plugin to the `server_plugins` list in `terraform.tfvars`:
```hcl
server_plugins = ["passcode", "oidc", "myplugin"]
```

This list defines which `AuthSvcId` values are valid for authentication.

***Logging and Monitoring Setup***: After deployment, improve log level configuration to facilitate timely detection and resolution of issues during actual application.

***Verify Plugin Loading***: Check server logs for plugin registration messages. The plugin registry logs which plugins are registered at startup.

**5. Production Environment Validation and Maintenance**

After the plugin deployment is complete, it is necessary to validate its functionality in the actual application environment to ensure that the plugin works correctly in the production environment. After the plugin goes live, regular maintenance should also be carried out to continuously monitor the plugin's performance, record operation data, and timely perform necessary updates and maintenance to ensure that the plugin remains in optimal condition during long-term use.

## Conclusion
Developing plugins for the NHP server can extend the server's functionality in a modular and maintainable way. By following the steps outlined above, you can create your own plugins and contribute to the NHP server project.





