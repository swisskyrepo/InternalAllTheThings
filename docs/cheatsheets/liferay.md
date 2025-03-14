# Liferay

> Liferay Portal is an open-source enterprise portal platform used for building web applications and digital experiences. It provides features like content management, user authentication, collaboration tools, and customizable dashboards. - [liferay/liferay-portal](https://github.com/liferay/liferay-portal)

## Summary

* [Portlets](#portlets)
* [Login Page](#login-page)
* [Register Page](#register-page)
* [User Profile](#user-configuration)
* [User Configuration](#user-configuration)
* [Control Panel](#control-panel)
* [API](#api)
* [Vulnerabilities](#vulnerabilities)
    * [Open Redirect](#open-redirect)
    * [Code Execution on Administrator Control Panel](#code-execution-on-administrator-control-panel)
    * [Resource Leakage Through I18nServlet](#resource-leakage-through-i18nservlet)
    * [Remote Code Execution via JSON web services](#remote-code-execution-via-json-web-services)
* [References](#references)

## Portlets

```ps1
/?p_p_id=<portlet_ID>&p_p_lifecycle=0&p_p_state=<window_state>&p_p_mode=<mode>
```

* **portlet_ID**: ID of the portlet to be executed. Can be a numeric ID, which is an incremental number for each portlet, or a [liferay.com/Fully-Qualified-Portlet-IDs](https://help.liferay.com/hc/en-us/articles/360018511712-Fully-Qualified-Portlet-IDs), which is a string.

* **window_state**: Amount of space a portlet takes up on a page. Values are: normal, maximized
minimized

* **mode**: Portlet's current function. Values are: view, edit, help

| Name                | Portlet ID |
| ------------------- | ---------- |
| Asset Publisher     | com_liferay_asset_publisher_web_portlet_AssetPublisherPortlet |
| Documents and Media | com_liferay_document_library_web_portlet_DLPortlet |
| Navigation Menu     | com_liferay_site_navigation_menu_web_portlet_SiteNavigationMenuPortlet |
| Site Map            | com_liferay_site_navigation_site_map_web_portlet_SiteNavigationSiteMapPortlet |
| Web Content Display | com_liferay_journal_content_web_portlet_JournalContentPortlet |
| Search Bar          | com_liferay_portal_search_web_search_bar_portlet_SearchBarPortlet |
| Search              | com_liferay_portal_search_web_portlet_SearchPortlet |

## Login Page

```ps1
/login
/c/portal/login
/?p_p_id=58&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view
/?p_p_id=58&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view&saveLastPath=false&_58_struts_action=%2Flogin%2Flogin
/?p_p_id=com_liferay_login_web_portlet_LoginPortlet&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view
/?p_p_id=com_liferay_login_web_portlet_LoginPortlet&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view&saveLastPath=false&_58_struts_action=%2Flogin%2Flogin
```

## Register Page

```ps1
/?p_p_id=58&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view&_com_liferay_login_web_portlet_LoginPortlet_mvcRenderCommandName=%2Flogin%2Fcreate_account
/?p_p_id=58&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view&saveLastPath=false&_58_struts_action=%2Flogin%2Flogin&_com_liferay_login_web_portlet_LoginPortlet_mvcRenderCommandName=%2Flogin%2Fcreate_account
/?p_p_id=com_liferay_login_web_portlet_LoginPortlet&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view&_com_liferay_login_web_portlet_LoginPortlet_mvcRenderCommandName=%2Flogin%2Fcreate_account
/?p_p_id=com_liferay_login_web_portlet_LoginPortlet&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view&saveLastPath=false&_58_struts_action=%2Flogin%2Flogin&_com_liferay_login_web_portlet_LoginPortlet_mvcRenderCommandName=%2Flogin%2Fcreate_account
```

## User Profile

```ps1
/web/<user>
/web/<user>/home
/user/<other_user>/control_panel/manage
/user/<other_user>/~/control_panel/manage
/web/guest
/web/guest/home
```

## User Configuration

```ps1
/user/<user>
/user/<user>/manage
/user/<user>/manage?p_p_id=com_liferay_my_account_web_portlet_MyAccountPortlet&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view
/group/control_panel/manage?p_p_id=com_liferay_my_account_web_portlet_MyAccountPo
```

## Control Panel

Endpoints reachable by authenticated users.

```ps1
/group/control_panel/manage
/group/guest/control_panel/manage
/group/guest/~/control_panel/manage
/group/<user>/control_panel/manage
/group/<user>/~/control_panel/manage
/user/<user>/control_panel/manage
/user/<user>/~/control_panel/manage
```

## API

* [nuclei-templates/http/misconfiguration/liferay/liferay-axis.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/liferay/liferay-axis.yaml)
* [nuclei-templates/http/misconfiguration/liferay/liferay-jsonws.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/liferay/liferay-jsonws.yaml)
* [nuclei-templates/http/misconfiguration/liferay/liferay-api.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/liferay/liferay-api.yaml)

| Name              | Path          |
| ----------------- | ------------- |
| JSON Web Services | `/api/jsonws` |
| SOAP              | `/api/axis`   |
| GraphQL           | `/o/graphql`  |
| JSON and GraphQL  | `/o/api`      |

## Vulnerabilities

* [liferay.dev/known-vulnerabilities](https://liferay.dev/portal/security/known-vulnerabilities)
* [ilmila/J2EEScan](https://github.com/ilmila/J2EEScan/blob/master/src/main/java/burp/j2ee/issues/impl/LiferayAPI.java)

### Open Redirect

```
/html/common/referer_jsp.jsp?referer=<url>
/html/common/referer_js.jsp?referer=<url>
/html/common/forward_jsp.jsp?FORWARD_URL=<url>
/html/common/forward_js.jsp?FORWARD_URL=<url>
```

### Code Execution on Administrator Control Panel

Gogo shell, read files

```ps1
/group/control_panel/manage?p_p_id=com_liferay_gogo_shell_web_internal_portlet_GogoShellPortlet&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view&_com_liferay_gogo_shell_web_internal_portlet_GogoShellPortlet_javax.portlet.action=executeCommand
```

Groovy Interpreter

```ps1
/group/control_panel/manage?p_p_id=com_liferay_server_admin_web_portlet_ServerAdminPortlet&p_p_lifecycle=0&p_p_state=maximized&p_p_mode=view&_com_liferay_server_admin_web_portlet_ServerAdminPortlet_mvcRenderCommandName=%2Fserver_admin%2Fview&_com_liferay_server_admin_web_portlet_ServerAdminPortlet_tabs1=script
```

### Resource Leakage Through I18nServlet

Liferay is vulnerable to local file inclusion in the I18n Servlet because it leaks information via sending an HTTP request to /[language]/[resource];.js (also .jsp works). [nuclei-templates/http/vulnerabilities/j2ee/liferay-resource-leak.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/j2ee/liferay-resource-leak.yaml)

* Liferay Portal 7.3.0 GA1
* Liferay Portal 7.0.2 GA3

### Remote Code Execution via JSON web services

* [nuclei-templates/http/cves/2020/CVE-2020-7961.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2020/CVE-2020-7961.yaml)

## References

* [Pentesting Liferay Applications - Víctor Fresco - February 6, 2025](https://www.tarlogic.com/blog/pentesting-liferay-applications/)
* [How to exploit Liferay CVE-2020-7961 : quick journey to PoC - Thomas Etrillard - March 30, 2020](https://www.synacktiv.com/en/publications/how-to-exploit-liferay-cve-2020-7961-quick-journey-to-poc.html)
