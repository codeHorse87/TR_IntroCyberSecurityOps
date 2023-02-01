<!--
author:   Marco Hammel

classroom: disable

email:    marco.hammel@agimo.eu

version:  1.0

language: en

narrator: US English Female

comment:  This is supporting material for an introductional 1/2 day workshop into cyber security operations.
          
-->

# Introduction into cyber security for IT professionals

The following contains supporting material for an introductional 1/2 day workshop into cyber security operations.
The material is not self-explanatory without the tranining workshop.

!?[ransomware song](https://youtu.be/d2dsI8NvdCU)

- [slides part1 download](https://github.com/codeHorse87/TR_IntroCyberSecurityOps/raw/main/presentation.pdf)


!?[disaster recovery song](https://youtu.be/uUZdCNyIOQc)

- [slides part2 download](https://github.com/codeHorse87/TR_IntroCyberSecurityOps/raw/main/presentation2.pdf)
- [Excercise part2 download](https://github.com/codeHorse87/TR_IntroCyberSecurityOps/raw/main/Exercise_BecomeACertAuthority.pdf)


## Prerequisites

- You have a general understanding about IT operations and common practices in this matter such as ITIL
- You have a general knowledge about IP-based networks including the relevant devices like routers, switches, firewalls, end points. 

## Learning Objectives

- You’re able to understand cyber security domains in the - context of application security
- You know root causes of security defects in software
- You know the concepts of adversarial frameworks for threat intelligence, threat hunting and emulation
- You can categorise defensive measures by their tactical - approach
- You can determine the applicability of deceptive and active countermeasures
- You understand common defensive tools processes and approaches. 


## Fundamentals of Application Security



### Learning Objectives

- You understand where application security fits into a cyber security domain model
- You can describe the limitations of different security layers 
- You know the relevance of input validation and output encoding 
- You can assess security traits of simple application workflows
- You understand possible causes of software security defects

### 1. Exercise - Contextual Validation of Input

The below flow diagram is a representation the implementation of a username and password-based authentication in a web-application. A login request is send from the client to the server in one http call consisting of a password and a user name. Based on the result of the comparison of the password hash stored for the user and the computed hash from the login request either a session id is returned to the client or HTTP 401 as a standard error code.

![image](/images/loginflow.png)


**Questions**

1. *For what kind of attack is this implementation at least vulnerable?*

    [( )] Remote code execution
    [(X)] Brute forcing 
    [( )] Denial of Service

2. *Which input validation is missing in the following implementation of a login routine?*

    [( )] Validation of the password strength
    [( )] Validation of the user name
    [(X)] Validation of a fail limit

3. *How can we fix the implementation of the login routine (multiple answers)?*

    [[X]] Implementation of and validation against a logon counter
    [[ ]] Implement a logging of logon attempts
    [[ ]] Implementation of a rate limit for client IPs 
    [[X]] Implement a user account lock and validate against the lock status

4. *What kind of security paradigm do you find appropriate here and why?*

    [( )] Defensive Programming
    [(X)] Offensive Programming
    [( )] Secure Programming


### Demo - FUZZing The golden ticket

A ticket agency runs a small webservice at http://static.208.217.55.162.clients.your-server.de. With this service a ruffle is connect to the cards of a concert. When your ticket has a certain ID, you get upgrade to a "Golden Ticket" with VIP backstage access. You've already tested your ticket by reading the QRCode resolving in the following URL: 

**http://static.208.217.55.162.clients.your-server.de/tickets/MQo=**

Let's see if you can figure out how the system works and how you can upgrade yourself to the "Golden Ticket"

### 2. Exercise - Breaking the Output Filter

This small JavaScript program should check the contents of the text input field "Input" for possible HTML control characters with the exception of controlling text formatting using **\<p\>**, **\<strong\>**, **\<br\>**, **\<em\>** and remove them from the input. All other input should be returned unchanged. Such kind of filter used to be typical in web forum software and content management systems. One wanted to give the users the possibility to format their forum entries with HTML as markup language. A common security issue for web applications is cross-site scripting. Whenever input from an untrusted source is put into the HTML page of a website without being properly encoded, there is a risk that an attacker can tamper the look and client-side code of a webpage rendered by the user's browser yielding to information theft, phising and tampering of the website's data.

Now test if you can get the forbidden HTML element **\<script\>** passing this filter. We have learned that such a form of input validation can be problematic if its purpose is to make the program's output harmless to the processor (in our case, the browser). Now the question arises how an attacker could bypass such a filter.

``` markdown
function filterInput(input) {
        return input.replace(
            '/<(\/*?)(?!(em|p|br\s*\/|strong))\w+?.+?>/g,
            '');
    }
```

---

__Result:__

[[<<script>script>]]
[[?]] Think about repeating yourself to make the filter return what you want
<script>
    let output = `@input`.replace(/<(\/*?)(?!(em|p|br\s*\/|strong))\w+?.+?>/g,'')
    // alert(output)
    if (output.includes('<script>')){
        //send.lia("That's correct",[], true)
        send.lia("true")
    } else {
        send.lia("Think about repeating yourself to make the filter return what you want", [], false)
    }
</script>


**Further References**

-	[OWASP Community Page XSS](https://owasp.org/www-community/attacks/xss/)
-	[XSS-Game by Google](https://xss-game.appspot.com/)

## Introduction to the Cyber Kill Chain

### 1. Exercise - Find the APT

We are investigating an incident in the organization and have determined that it is related to a threat group called Fox Kitten. After getting initial access to the network, they were able to use Windows system internal tools (PsExec) to create a domain account to maintain access within the network.

1. Navigate to Threat Groups on the Mitre website ([https://attack.mitre.org/groups/](https://attack.mitre.org/groups/))
2. Search for the Threat Group in the scenario  
3. Find the software they used to maintain access and list four techniques the tool can be used for 
4. Preview the ATT&CK navigator to determine for which tactics the tool can be useful for 

*What's the name of the group*

    [( )] Fancy Bear
    [(X)] Fox Kitten
    [( )] Cozy Bear

## Understanding the Adversary

### Demo - Canary Tokens

Canary tokens are a type of deception technology used in cybersecurity to detect and track unauthorized access or suspicious activity on a network or system. They are used to create a "canary trap" by placing a unique token, such as a file or code, in a location that an attacker is likely to access. If the canary token is accessed or tampered with, it sends an alert to the security team, indicating that an unauthorized access has occurred. This allows the security team to quickly detect and respond to a potential attack. The canary token can be used in many ways such as in email links, files, scripts, etc. The basic principle is to place a token in a location that is likely to be accessed by an attacker and set up an alert system when that token is accessed.

Thinkst Canary is a provide of different tokens setups. There are tokens available for free at [https://canarytokens.org/generate](https://canarytokens.org/generate)

### Demo - Spider Trap

A web crawler trap, also known as a spider trap, is a technique used to identify and block unwanted web crawlers or spiders from accessing a website. These traps are designed to detect and redirect automated bots, such as search engine spiders or malicious bots, away from sensitive areas of a website. They can be implemented in a number of ways, such as by using JavaScript code or special URLs that are only accessible by web crawlers. When a web crawler or spider accesses the trap, it is redirected away from the main website, preventing it from collecting sensitive information or causing harm. The goal of the trap is to identify unwanted crawlers and stop them from accessing and potentially harming the website. As a result, such a trap will slow down the attacker while carrying out recon activities and will also make them more cautionous as soon as they recognize that deception technology is in place. 

Example: [https://trap.academy.no-monkey.com/](https://trap.academy.no-monkey.com/)
