# plugin-adapter

### Deployment Process
```
# Create AWS ECR Repository
aws ecr create-repository --repository-name cloudchainsapp/plugin-adapter

# Build Dockerfile
docker build -t <account_id>.dkr.ecr.us-east-1.amazonaws.com/cloudchainsapp/plugin-adapter .

# Push to ECR
docker push <account_id>.dkr.ecr.us-east-1.amazonaws.com/cloudchainsapp/plugin-adapter

# Deploy application to kubernetes
kubectl apply -f deployment.yml
```
