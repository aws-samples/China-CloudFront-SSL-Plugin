# China CloudFront SSL Plugin - CDK Code

This section contains CDK code with TypeScript for China CloudFront SSL Plugin.

## Build Guide

To generate cloudformation, please modify Account ID and Amazon ECR (Amazon Elastic Container Registry) pushed for [Lambda Code](../lambda/README.md) in [`china-cloudfront-ssl-plugin-stack.ts`](lib%2Fchina-cloudfront-ssl-plugin-stack.ts) before export to CloudFormation , and then execute the following commands:

```
$ npm install
$ cdk synth --path-metadata false --version-reporting false
```

Then you can find CloudFormation Template(ChinaCloudFrontSslPluginStack.template.json) in cdk.out folder.