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

## Web Content

- "img-comparison-slider" by sneas
  - [GitHub Repo](https://github.com/sneas/img-comparison-slider)

## Container

Start your cluster using `minikube start`.

Ensure you're in the docker enviroment using `eval $(minikube docker-env)`.

Build the app using `docker build -t maple-glow-app .`.

Apply the kubernetes configs `kubectl apply -f deployment.yaml` and `kubectl apply -f service.yaml`.

Start the service `minikube service maple-glow-service`.

## Authors

Owen, Veloan, and Mohnish
