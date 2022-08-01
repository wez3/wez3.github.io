---
title: 'Building: Did someone clone me?'
author: wesley
layout: post
---
Last months I've been working on a new project called <a href="https://didsomeoneclone.me">didsomeoneclone.me</a>. Last years I've been analyzing many phishing websites for fun. 
During those analysis I realized that many companies could improve on detecting clones of their websites. Techniques are available and even not hard to implement, but often not used.

The goal of did someone clone me is to:

> A free service that notifies its users when their website is cloned and used in a phishing attack. This allows them to be aware of the attacks and brand abuse, but also take necessary mitigations such as initiating a takedown or investigating the phishing site.

A video explaining the concept:

<iframe width="560" height="315" src="https://www.youtube.com/embed/Vn6cuEaXwYw" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

<!--more-->

# Why?

First of all, I do think that detecting clones of a website can help fight phishing. Phishing is a huge problem nowadays. 
It helps you to take necessary steps such as initiating a takedown, informing users / customers and performing investigation.
Also, it doesn't hurt to implement this. Hopefully your website never gets cloned so you will not receive any notifications. But if it does, you will get notified. Doesn't that feel good?

Next to this I just like to build stuff. Preferaly with the newest technologies, just to learn the newest things. Important in breaking stuff ;-).

# How was it built?

While brainstorming on how to built this, I found some things important:
* no maintenance
* low costs

Maintainance, I don't like. Especially because this is a side project. I want to build it and it needs to keep running .. :-). 
I decided to use cloud services, they offer amazing techniques to built services on and often with lower costs. 

## Azure Functions and Tables

The core of did someone clone me consists of two Azure Function. I really like Azure Function because they are serverless. It's essentially a Python script (or other language) running in the cloud. Microsoft maintaince all servers that will run your Python script. It scales up the required resources automatically. Also, you only pay Microsoft when your script executes.

### API

The service requires users to register with their domain and e-mail address on a website. The <a href="https://didsomeoneclone.me">didsomeoneclone.me</a> website uses this API to allow users to register. Also e-mail confirmation go through this API. 
The data (e-mail and domain) are stored in Azure Tables, which is a NoSQL datastore.

![API](/uploads/2022/07/api.svg)

### Callback

Another function is used as the "callback" function. Did someone clone me requires a registered user to add a link to their website (<a href="https://didsomeoneclone.me/examples/">HTML/JS examples can be found here</a>). The link points to this Azure Function. It contains all logic to detect if a request was originated from the real users website or a phishing site. 

![Callback](/uploads/2022/07/callback.svg)

### CI/CD

This was something new to me. Azure Functions integrate flawless with Github. When new code is pushed to Github, its automatically deployed to a Azure Function:
* when pushing to the Github 'develop' branch, the code is deployed in a test environment
* when pushing to the Github 'master' branch, the code is deployed to production 

No manual deployment anymore ❤️

## Github Pages

I really like Github pages. Its a way to host a website / frontend for free. Also, its static: which means its hard to hack. In the end its just a bunch of generated HTML and JavaScript code.
The frontend <a href="https://didsomeoneclone.me">didsomeoneclone.me</a> is based on Github pages, it calls the earlier mentioned Azure Function API's through JavaScript. 
The <a href="https://github.com/didsomeonecloneme/didsomeonecloneme.github.io">source code is available here</a>, please don't clone it... ;-)
The frontend:

![Frontend](/uploads/2022/07/frontend.png)

## Sendgrid

Did someone clone me requires sending e-mails for confirming the e-mail address and sending notifications. I didn't want to spend to many time on building e-mail templates. Sendgrid offers an easy to use e-mail designer. 
Also, it doesn't require any maintaince and e-mails can be easily send through Python (aka the Azure Functions)!
A mail example:

<img src="/uploads/2022/07/dscm-mail.png" style="width:50%;">

## Cloudflare
Its not necessary, but they offer great services that might be useful when the project grows.

# Conclusion

Hopefully other people also see the benefit of implementing did someone clone me and start using it. Otherwise, it was fun to build and I've learned new stuff!
