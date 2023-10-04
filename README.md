# Wallet Login Demo
A project that demonstrates how to use a MetaMask wallet as a mechanism for website login and authentication.

This application consists of two parts. The first part is the web server. The second part is the client side web page that's used to access logic hosted on the web server.

The source code for the web server is located at [./src/server.js](./src/server.js).

The web page HTML is located at [./src/public/index.html](./src/public/index.html). The client side logic used by the HTML in the web page is located at [./src/public/functions.js](./src/public/functions.js).

# System requirements

- [Node.js®](nodejs.org) needs to be installed on the machine running the source code.
- A web browser with the MetaMask plugin installed. For instructions on how install MetaMask in a web browser go [here](https://metamask.io/download/).

# Installing the application

In a terminal window execute the following command:

```bash
git clone https://github.com/BlockchainJournal/Wallet-Login-Demo.git
```

The application's source code will be downloaded into a folder named `Wallet-Login-Demo`.


# Installing the application dependencies

**Step 1:** In a terminal window execute the following commands:

```bash
cd ./Wallet-Login-Demo
```

```bash
npm install
```

# Starting the web server

In a terminal window execute the following command:

**Step 1:** In a terminal window execute the following command:

```bash
npm start
```

You'll see the following output:

`Server is running on port 3111`

# Authenticating to the application using MetaMask

**Step 1:** Using a browser that has the MetaMask plugin installed, go to the URL

```bash
http://localhost:3111
```

You'll see the following web page. 

![Screenshot 2023-10-03 at 11 08 07 AM](https://github.com/reselbob/SimpleWeb3Auth/assets/1110569/f550f9be-b9fd-482f-8858-0f631f1d6afe)

**Step 2:** Click the button labeled `Login with MetaMask`. Clicking the button will present the MetaMask plugin UI.

![Screenshot 2023-10-03 at 11 29 26 AM](https://github.com/reselbob/SimpleWeb3Auth/assets/1110569/c19ad37a-67f8-4b10-bf18-2ebc8f241652)

**Step 3:** Click the button labeled `Sign` in the lower right of the MetaMask plugin to log in to the website.

Clicking the `Sign` button will make it so that you'll be authenticated to the demonstration website using MetaMask's validation mechanisms.

# Declaring a profile

The first time you login to the demonstration application you will be asked to declare a profile by filling in the following form:

![Screenshot 2023-10-03 at 11 29 57 AM](https://github.com/reselbob/SimpleWeb3Auth/assets/1110569/6fe5bdca-e7f7-4b51-9b7f-9f6db1003eab)

**Step 1:** Fill in the data fields in the form.

![Screenshot 2023-10-03 at 11 31 00 AM](https://github.com/reselbob/SimpleWeb3Auth/assets/1110569/48d81246-4332-4486-a25f-40d82bbffe4d)

**Step 2:** Click the button labeled `Submit User Profile`.

The profile will be saved and the declaration form will become read only.

**Step 3:** Refresh the web page in your web browser and login once again.

This time because the application has record of your profile, you'll be presented with a greeting particular to your profile along with the account address you used with MetaMask.

![Screenshot 2023-10-03 at 11 31 20 AM](https://github.com/reselbob/SimpleWeb3Auth/assets/1110569/489305fa-a06e-4dbe-b954-5b2a7fe52e97)







