# Android Application

## Lab

* [payatu/diva-android](https://github.com/payatu/diva-android) - Damn Insecure and vulnerable App for Android
* [HTB VIP - Pinned](https://app.hackthebox.com/challenges/282) - Hack The Box challenge
* [HTB VIP - Manager](https://app.hackthebox.com/challenges/283) - Hack The Box challenge


## Extract APK

### ADB Method

Connect to ADB shell and list/download packages.
You might need to enable `Developer mode` and `Debugging` in order to connect with `adb`

```powershell
adb shell pm list packages
adb shell pm path com.example.someapp
adb pull /data/app/com.example.someapp-2.apk
```

### Stores

Warning: Downloading APK files from unofficial stores can compromise your device's security. These sources often host malware and malicious software. Always use trusted and official app stores for downloads.

* [Google Play](https://play.google.com/store/apps) - Official Store
* [Apkpure.fr](https://apkpure.fr/fr/) - Alternative to Google Play
* [Apkpure.co](https://apkpure.co) - Alternative to Google Play
* [Aptoide](https://fr.aptoide.com/) - Alternative to Google Play
* [Aurora Store](https://f-droid.org/fr/packages/com.aurora.store/) - Alternative to Google Play

Download APK from Google Play using a 3rd Party:

* [apkcombo.com](https://apkcombo.com/downloader/)
* [apps.evozi.com](https://apps.evozi.com/apk-downloader/)


## Static Analysis

### Extract Contents From APK

Search for strings `flag`,`secret`, the default string file is `Resources/resources.arsc/res/values/strings.xml`.

```powershell
apktool d application.apk
```

### Decompile Data as Java Code

* Rename `application.apk` to `application.zip`: `mv application.apk application.zip`
* Extract `classes.dex`: `unzip application.zip`
* Use `dex2jar` to obtain a jar file: `/usr/bin/d2j-dex2jar classes.dex`
* Use `jadx` using full CPU: `jadx classes.dex -j $(grep -c ^processor /proc/cpuinfo) -d Downloads/app/ > /dev/null`
    ```powershell
    jadx-gui
    --deobf # remove obfuscation by AndroGuard
    -e      # generate a gradle project for Android Studio (easy to find function)
    ```

To reverse `.odex` you need to provide the `/system/framework/arm`, fortunately since we have the firmware we have it.

```powershell
java -jar baksmali-2.3.4.jar x application.odex -d k107-mb-8.1/system/framework/arm -o application
apktool d application.apk 
apktool b rebuild_folder -o rebuilt.apk
```


### Decompile Native Code

Native library are represented as `.so` files.    
These libraries by default are included in the APK at the file path `/lib/<cpu>/lib<name>.so` or `/assets/<custom_name>`.

Use `IDA`, `Radare2/Cutter` or `Ghidra` to reverse them.

| CPU	Native         | Library Path                |
|----------------------|-----------------------------|
| "generic" 32-bit ARM | lib/armeabi/libcalc.so      |
| x86                  | lib/x86/libcalc.so          |
| x64                  | lib/x86_64/libcalc.so       |
| ARMv7                | lib/armeabi-v7a/libcalc.so  |
| ARM64                | lib/arm64-v8a/libcalc.so    |

:warning: The shared object file (`.so`) doesn't need to be embedded in the app. 


### Sign and Package APK

* `apktool` + `jarsigner`
    ```powershell
    apktool b ./application.apk
    keytool -genkey -v -keystore application.keystore -alias application -keyalg RSA -keysize 2048 -validity 10000
    jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore application.keystore application.apk application
    zipalign -v 4 application.apk application-signed.apk
    ```
* `apktool` + `signapk`
    ```powershell
    apktool b app-release
    ./signapk app-release/dist/app-release.apk
    ```

* [patrickfav/uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) (Linux only)
    ```powershell
    java -jar uber-apk-signer.jar --apks /path/to/apks
    ```
* [APK Toolkit v1.3](https://xdaforums.com/t/tool-apk-toolkit-v1-3-windows.4572881/) (Windows only)


### Mobile Security Framework Static

> Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.

* [MobSF - Documentation](https://mobsf.github.io/docs/#/)
* [MobSF - Github](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
* [MobSF - Live Demo](https://mobsf.live/)

Run [MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

* Latest version from DockerHub
    ```powershell
    docker run -it --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
    ```
* Enable persistence on the Docker container
    ```powershell
    docker run -it --rm --name mobsf -p 8000:8000 -v <your_local_dir>:/root/.MobSF opensecurity/mobile-security-framework-mobsf:latest
    ```


### Online Assets

:warning: Uploading APKs to uncontrolled websites risks data leaks, malware, intellectual property theft, and privacy violations. Use trusted platforms only to ensure the security and integrity of your app.

* [appetize.io](https://appetize.io/) - Instantly run mobile apps in your browser
* [mobsf.live](https://mobsf.live/) - Demo version of MobSF
* [hybrid-analysis.com](https://www.hybrid-analysis.com/sample/573df0b1cb5ffc0a25306be5ec83483ed1b2acdba37dd93223b9f14f42b2fdea?environmentId=200) - Sandbox analysis of APK files


### React Native and Hermes

Identify React Native app with `index.android.bundle` inside the `assets` folder

```ps1
Hermes: pip install hbctool
╰─$ hbctool disasm index.android.bundle indexasm
[*] Disassemble 'index.android.bundle' to 'indexasm' path
[*] Hermes Bytecode [ Source Hash: 4013cb75f7e16d4474f5cf258edc45ee16585560, HBC Version: 74 ]
[*] Done
```


### Flutter

Indentify Flutter use in the `MANIFEST.MF` and search for `libflutter.so`.

* [worawit/blutter](https://github.com/worawit/blutter) - Flutter Mobile Application Reverse Engineering Tool
    ```ps1
    blutter jadx/resources/lib/arm64-v8a/ ./blutter_output
    ```


## Dynamic Analysis

Dynamic analysis for Android malware involves executing and monitoring an app in a controlled environment to observe its behavior. This technique detects malicious activities like data exfiltration, unauthorized access, and system modifications. Additionally, it aids in reverse engineering app features, revealing hidden functionalities and potential vulnerabilities for better threat mitigation.


### Burp Suite

* Proxy > Listen to all interfaces
* Import/Export CA certificate
* `adb push burp.der /sdcard/burp.crt`
* Open the Settings on the device and search "Install Cert"
* Click Install certificates from SD card
* Configure the AVD to use the proxy


### Frida

* [Frida - Documentation](https://frida.re/docs/android)
* [Frida - Github](https://github.com/frida/frida/)

Download [`frida`](https://github.com/frida/frida/releases) from releases.

```ps1
pip install frida-tools
unxz frida-server.xz
adb root # might be required
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

Interesting Frida scripts:

* [Universal Android SSL Pinning Bypass with Frida](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/) -  `frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f YOUR_BINARY`
* [frida-multiple-unpinning](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/) - `frida --codeshare akabe1/frida-multiple-unpinning -f YOUR_BINARY`
* [aesinfo](https://codeshare.frida.re/@dzonerzy/aesinfo/) - `frida --codeshare dzonerzy/aesinfo -f YOUR_BINARY`
* [fridantiroot](https://codeshare.frida.re/@dzonerzy/fridantiroot/) - `frida --codeshare dzonerzy/fridantiroot -f YOUR_BINARY`
* [anti-frida-bypass](https://codeshare.frida.re/@enovella/anti-frida-bypass/) - `frida --codeshare enovella/anti-frida-bypass -f YOUR_BINARY`
* [xamarin-antiroot](https://codeshare.frida.re/@Gand3lf/xamarin-antiroot/) - `frida --codeshare Gand3lf/xamarin-antiroot -f YOUR_BINARY`
* [Intercept Android APK Crypto Operations](https://codeshare.frida.re/@fadeevab/intercept-android-apk-crypto-operations/) - `frida --codeshare fadeevab/intercept-android-apk-crypto-operations -f YOUR_BINARY`
* [Android Location Spoofing](https://codeshare.frida.re/@dzervas/android-location-spoofing/) - `frida --codeshare dzervas/android-location-spoofing -f YOUR_BINARY`
* [java-crypto-viewer](https://codeshare.frida.re/@Serhatcck/java-crypto-viewer/) - `frida --codeshare Serhatcck/java-crypto-viewer -f YOUR_BINARY`


### Runtime Mobile Security

> Runtime Mobile Security (RMS) 📱🔥 - is a powerful web interface that helps you to manipulate Android and iOS Apps at Runtime

* [RMS - Github](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security)

**Requirements**:
* `adb`
* `frida`: server up and running on the target device

In case of issue with your favorite Browser, please use Google Chrome (fully supported).   

* Install RMS
    ```powershell
    npm install -g rms-runtime-mobile-security
    ```
* Make sure `frida-server` is up and running on the target device.
* Launch RMS: `rms`
* Open your browser at http://127.0.0.1:5491/
* Attach to the app, find name with `adb shell pm list package | grep NAME`


### Genymotion

Genymotion is a robust Android emulator designed for developers, offering fast and reliable virtual devices for app testing. It features GPS, battery, and network simulation, enabling comprehensive testing and development

* [Genymotion](https://www.genymotion.com/)
* [Genymotion Desktop](https://www.genymotion.com/product-desktop/)
* [Genymotion Device Image](https://www.genymotion.com/product-device-image/)
* [Genymotion SaaS](https://www.genymotion.com/product-cloud/)


### Android SDK emulator

Android Virtual Device (AVD) without Google Play Store.

* Download the files for an API 25 build
    ```powershell 
    sdkmanager "system-images;android-25;google_apis;x86_64"
    ```

* Create a device based on what we downloaded previously
    ```powershell 
    avdmanager create avd x86_64_api_25 -k "system-images;android-25;google_apis;x86_64"
    ```

* Run the emulator
    ```powershell 
    emulator @x86_64_api_25

    emulator -list-avds
    emulator -avd <non_production_avd_name> -writable-system -no-snapshot
    emulator -avd Pixel_XL_API_31 -writable-system -http-proxy 127.0.0.1:8080
    ```

* Install the APK
    ```powershell 
    adb install ./challenge.apk
    ```

* Start the App
    ```powershell 
    adb shell monkey -p com.scottyab.rootbeer.sample 1
    ```


### Mobile Security Framework Dynamic

:warning: Dynamic Analysis will not work if you use MobSF docker container or setup MobSF inside a Virtual Machine.

**Requirements**:
* Genymotion (Supports x86_64 architecture Android 4.1 - 11.0, upto API 30)
    * Android 5.0 - 11.0 - uses Frida and works out of the box with zero configuration or setup.
    * Android 4.1 - 4.4 - uses Xposed Framework and requires MobSFy
* Genymotion Cloud
    * [Amazon Marketplace - TCP 5555](https://aws.amazon.com/marketplace/seller-profile?id=933724b4-d35f-4266-905e-e52e4792bc45)
    * [Azure Marketplace - TCP 5555](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/genymobile.genymotion-cloud)
* Android Studio Emulator (only Android images upto API 28 are supported)
    * AVD without Google Play Store

Dynamic Analysis from MobSF grants you the following features:
* Web API Viewer
* Frida API Monitor


### Appium

Appium is an open-source project and ecosystem of related software, designed to facilitate UI automation of many app platforms, including mobile (iOS, Android, Tizen), browser (Chrome, Firefox, Safari), desktop (macOS, Windows), TV (Roku, tvOS, Android TV, Samsung), and more!

* Install appium: `npm install -g appium`
* Install and validate the `uiautomator2` driver
    ```ps1
    export JAVA_HOME=/usr/lib/jvm/default-java
    export ANDROID_HOME=/home/user/Android/Sdk/
    wget https://github.com/google/bundletool/releases/download/1.17.1/bundletool-all-1.17.1.jar
    sudo mv bundletool-all-1.17.1.jar /usr/local/bin
    appium driver install uiautomator2
    appium driver doctor uiautomator2
    ```
* Start the server on the default host (0.0.0.0) and port (4723): `appium server`
* Install the Appium Python client: `pip install Appium-Python-Client`
* Use the [appium/appium-inspector](https://github.com/appium/appium-inspector) with the following capability
    ```json
    {
    "platformName": "Android",
    "appium:automationName": "UiAutomator2"
    }
    ```

Examples:

* [quickstarts/py/test.py](https://github.com/appium/appium/blob/master/packages/appium/sample-code/quickstarts/py/test.py)
* [quickstarts/js/test.js](https://github.com/appium/appium/blob/master/packages/appium/sample-code/quickstarts/js/test.js)
* [quickstarts/js/test.rb](https://github.com/appium/appium/blob/master/packages/appium/sample-code/quickstarts/rb/test.rb)


### Flutter

Repackage a Flutter Android application to allow Burp Suite proxy interception.

* [ptswarm/reFlutter](https://github.com/ptswarm/reFlutter) - Flutter Reverse Engineering Framework
    ```
    pip3 install reflutter
    reflutter application.apk
    ```
* Sign the apk with [patrickfav/uber-apk-signer](https://github.com/patrickfav/uber-apk-signer/releases/tag/v1.2.1) 
    ```ps1
    java -jar ./uber-apk-signer-1.3.0.jar --apks release.apk
    java -jar ./uber-apk-signer.jar --allowResign -a release.RE.apk
    ```

An alternative way to do it is using a rooted Android device with `zygisk-reflutter`.

* [yohanes/zygisk-reflutter](https://github.com/yohanes/zygisk-reflutter) - Zygisk-based reFlutter (Rooted Android with Magisk installed and Zygisk Enabled)
    ```ps1
    adb push  zygiskreflutter_1.0.zip /sdcard/
    adb shell su -c magisk --install-module /sdcard/zygiskreflutter_1.0.zip
    adb reboot
    ```


## SSL Pinning Bypass

SSL certificate pinning in an APK involves embedding a server's public key or certificate directly into the app. This ensures the app only trusts specific certificates, preventing man-in-the-middle attacks by rejecting any certificates not matching the pinned ones, even if they are otherwise valid.

:warning: Android 9.0 is changing the defaults for Network Security Configuration to block all cleartext traffic.

* [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) - A CLI application that automatically prepares Android APK files for HTTPS inspection
    ```powershell
    $ npx apk-mitm application.apk
    npx: 139 installé(s) en 12.206s
    ╭ apk-mitm v0.6.1
    ├ apktool v2.4.1
    ╰ uber-apk-signer v1.1.0
    Using temporary directory:
    /tmp/87d3a4921ddf86cde634205480f89e90
    ✔ Decoding APK file
    ✔ Modifying app manifest
    ✔ Modifying network security config
    ✔ Disabling certificate pinning
    ✔ Encoding patched APK file
    ✔ Signing patched APK file
    Done!  Patched file: ./application.apk
    ```
* [51j0/Android-CertKiller](https://github.com/51j0/Android-CertKiller) - An automation script to bypass SSL/Certificate pinning in Android
    ```powershell
    $ python main.py -w #(Wizard mode)
    $ python main.py -p 'root/Desktop/base.apk' #(Manual mode)
    ```
* [frida/frida](https://github.com/frida/frida) - Universal SSL Pinning Bypass
    ```javascript
    $ adb devices
    $ adb root
    $ adb shell
    $ phone:/# ./frida-server

    // https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
    $ frida -U --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f com.example.pinned

    $ frida -U -f org.package.name -l universal-ssl-check-bypass.js --no-pause
    Java.perform(function() {                
        var array_list = Java.use("java.util.ArrayList");
        var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        ApiClient.checkTrustedRecursive.implementation = function(a1,a2,a3,a4,a5,a6) {
            var k = array_list.$new(); 
            return k;
        }
    },0);
    ```
* [m0bilesecurity/RMS-Runtime-Mobile-Security](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security) - Certificate Pinning bypass script (all + okhttpv3)
* [federicodotta/Brida](https://github.com/federicodotta/Brida) - The new bridge between Burp Suite and Frida


## Root Detection Bypass

Common root detection techniques:

* Su binaries: `su`/`busybox`
* Known Root Files/Paths : `Superuser.apk`
* Root Management Apps: `Magisk`, `SuperSU `
* RW paths:  `/system`, `/data` directories
* System Properties

Common bypass:

* [fridantiroot](https://codeshare.frida.re/@dzonerzy/fridantiroot/) - `frida --codeshare dzonerzy/fridantiroot -f YOUR_BINARY`
* [xamarin-antiroot](https://codeshare.frida.re/@Gand3lf/xamarin-antiroot/) - `frida --codeshare Gand3lf/xamarin-antiroot -f YOUR_BINARY`
* [multiple-root-detection-bypass/](https://codeshare.frida.re/@KishorBal/multiple-root-detection-bypass/) - `frida --codeshare KishorBal/multiple-root-detection-bypass -f YOUR_BINARY`


## Android Debug Bridge

Android Debug Bridge (ADB) is a versatile command-line tool that enables communication between a computer and an Android device. It facilitates tasks like installing apps, debugging, accessing the device's shell, and transferring files, making it essential for developers and power users in Android development and troubleshooting.

| Command                      | Description                                    |
|------------------------------|------------------------------------------------|
| `adb devices`                | List devices                                   |
| `adb connect <IP>:<PORT>`    | Connect to a remote device                     |
| `adb install app.apk`        | Install application                            |
| `adb uninstall app.apk`      | Uninstall application                          |
| `adb root`                   | Restarting adbd as root                        |
| `adb shell pm list packages` | List packages                                  |
| `adb shell pm list packages -3` | Show third party packages                   |
| `adb shell pm list packages -f` | Show packages and associated files          |
| `adb shell pm clear com.test.abc` | Delete all data associated with a package |
| `adb pull <remote> <local>`  | Download file                                  |
| `adb push <local> <remote>`  | Upload file                                    |
| `adb shell screenrecord /sdcard/demo.mp4`| Record video of the screen         |
| `adb shell am start -n com.test.abc` | Start an activity                      |
| `adb shell am startservice ` | Start a service                                |
| `adb shell am broadcast `    | Send a broadcast                               |
| `adb logcat *:D`             | Show log with Debug level                      |
| `adb logcat -c`              | Clears the entire log                          |


## Android Virtual Device

An Android Virtual Device (AVD) is an emulator configuration that mimics a physical Android device. It allows developers to test and run Android apps in a simulated environment with specific hardware profiles, screen sizes, and Android versions, facilitating app testing without needing actual devices.

```ps1
emulator -avd Pixel_8_API_34 -writable-system
```

| Command                      | Description                                    |
|------------------------------|------------------------------------------------|
| `-tcpdump /path/dumpfile.cap`| Capture all the traffic in a file |
| `-dns-server X.X.X.X`        | Set DNS servers |
| `-http-proxy X.X.X.X:8080`   | Set HTTP proxy |
| `-port 5556`                 | Set the ADB TCP port number |


## Unlock Bootloader

**Requirements**:

* Enable `Settings` > `Developer Options` > `OEM unlocking`
* Enable `Settings` > `Developer Options` > `USB Debugging`

Unlock the bootloader will wipe the userdata partition. On some device these methods will require a key to successfully unlock the bootloader.

* Method 1
    ```ps1
    adb reboot bootloader
    fastboot oem unlock
    ```
* Method 2
    ```ps1
    adb reboot bootloader
    fastboot flashing unlock
    ```
* Methods based on the chip
    * For Qualcomm devices, you can use EDL (Emergency Download Mode)
    * For MediaTek devices, BROM (Boot ROM) mode
    * For Unisoc devices, Research Download Mode.


## References

* [Android App Reverse Engineering 101 - @maddiestone](https://www.ragingrock.com/AndroidAppRE/)
* [Android app vulnerability classes - Google Play Protect](https://static.googleusercontent.com/media/www.google.com/fr//about/appsecurity/play-rewards/Android_app_vulnerability_classes.pdf)
* [Mobile Systems and Smartphone Security - @reyammer](https://mobisec.reyammer.io)
* [Configuring Frida with BurpSuite and Genymotion to bypass Android SSL Pinning - arben](https://spenkk.github.io/bugbounty/Configuring-Frida-with-Burp-and-GenyMotion-to-bypass-SSL-Pinning/)
* [Configuring Burp Suite With Android Nougat - ropnop - January 18, 2018](https://blog.ropnop.com/configuring-burp-suite-with-android-nougat)
* [Configuring Burp Suite with Android Emulators - Aashish Tamang - Jun 6, 2022](https://blog.yarsalabs.com/setting-up-burp-for-android-application-testing/)
* [Introduction to Android Pentesting - Jarrod - July 8, 2024](https://owlhacku.com/introduction-to-android-pentesting/)
* [A beginners guide to using Frida to bypass root detection. - DianaOpanga - Nov 27, 2023](https://medium.com/@dianaopanga/a-beginners-guide-to-using-frida-to-bypass-root-detection-16af76b989ac)
* [Appium documentation](https://appium.io/docs/en/latest/)
* [How to root an Android device for analysis and vulnerability assessment - Joe Lovett - 23 Aug 2024](https://www.pentestpartners.com/security-blog/how-to-root-an-android-device-for-analysis-and-vulnerability-assessment/)