# ICS4U Final Project

Full stack website for **Maple Glow Car Detailing Services**.

## Languages

- HTML
- CSS
- JavaScript

## Frameworks

- Node.js
- Express.js
- EJS

## Database

- MongoDB

## API

- Teachable Machine
  - [Teachable Machine Website](https://teachablemachine.withgoogle.com/)

## Local setup

Copy `.env.example` to `.env` and set real values for:

- `MONGODB_URI`
- `SESSION_SECRET`
- `EMAIL_PASSWORD`
- `ADMIN_USERNAMES`

Then run:

```sh
npm install
npm start
```

Do not commit `.env` or real Kubernetes secret manifests. The previous checked-in credentials should be considered exposed and rotated.

## Container

Start your cluster using `minikube start`.

Ensure you're in the docker enviroment using `eval $(minikube docker-env)`.

Build the app using `docker build -t maple-glow-app .`.

Create a real secret from `secret.example.yaml`, then apply the kubernetes configs `kubectl apply -f secret.yaml`, `kubectl apply -f deployment.yaml` and `kubectl apply -f service.yaml`.

Start the service `minikube service maple-glow-service`.

## Free hosting

Use Render's free Web Service for the Node/Express app and MongoDB Atlas Free Cluster for the database. Set the environment variables in Render, use `npm install` as the build command, and use `npm start` as the run command. Render free Web Services block outbound SMTP ports, so switch the mailer to an HTTPS email API provider before relying on contact, booking, or password-recovery emails in that environment.

## Authors

Owen, Veloan, and Mohnish
