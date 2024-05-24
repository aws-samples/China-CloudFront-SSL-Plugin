FROM public.ecr.aws/lambda/nodejs:18-x86_64

# Install the function's dependencies using file requirements.txt
# from your project folder.

COPY package.json ${LAMBDA_TASK_ROOT}
RUN  npm install

# Copy function code
COPY app.json ${LAMBDA_TASK_ROOT}
COPY app.js ${LAMBDA_TASK_ROOT}

# Set the CMD to your handler (could also be done as a parameter override outside of the Dockerfile)
CMD [ "app.handler" ]