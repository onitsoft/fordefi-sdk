echo "Input the fordefi.jfrog docker registry password provided by Fordefi team"
docker login -ufordefi fordefi.jfrog.io
echo "Pulling docker image..."
docker pull fordefi.jfrog.io/fordefi/api-signer:latest
