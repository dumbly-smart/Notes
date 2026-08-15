

![[Pasted image 20260708132257.png]]


 ML follows a structured lifecycle. It starts with defining the problem, for example, determining whether an email is spam. Data is then collected, cleaned, and prepared. The model is trained on that data, then evaluated and tuned until it performs well. Once it's ready, it gets deployed into a real-world environment. But the lifecycle doesn't stop at deployment. Models require ongoing monitoring and periodic retraining as the world changes around them, which is what makes it an iterative process rather than a one-and-done job.


## Overfitting

One term worth flagging here is overfitting. This is when a model becomes so familiar with its that it fails to generalise to new, unseen data. Rather than learning the underlying pattern, it essentially memorises the examples it was trained on. You'll hear this term come up again later in the path, particularly in a security context.


## ML

ML algorithms are the mathematical methods used to learn patterns from data. The trained outputs they produce are what we call models. Every algorithm follows the same basic structure: a **decision process** that makes predictions based on input data, an **error function** that evaluates how far off those predictions were, and a **model optimisation process** that adjusts the algorithm to do better next time. This loop repeats until the model reaches a satisfactory level of performance.

![[Pasted image 20260708133949.png]]


**Supervised learning** trains on labelled data, meaning every training example comes with the correct answer already attached. The model learns to map inputs to outputs based on those examples. Predicting house prices or classifying whether an email is spam are both supervised learning problems.

**Unsupervised learning** works with unlabelled data and has to find its own structure. Rather than being told what the answer is, the algorithm identifies patterns, clusters, and relationships in the data on its own. It's useful for things like grouping customers by behaviour or detecting anomalies in network traffic.

**Semi-supervised learning** sits between the two. It uses a small portion of labelled data to guide the learning process across a much larger pool of unlabelled data. This is practical in situations where labelling data is expensive or time-consuming.

**Reinforcement learning** works differently from all three. Rather than learning from a fixed dataset, an agent learns by taking actions in an environment and receiving rewards or penalties based on the outcomes. Over time, it refines its behaviour to maximise reward. It's the approach behind things like game-playing and autonomous systems.

## Neural network

A neural network is made up of layers of nodes, where each node represents a neuron and each connection between nodes acts as a synapse. The **input layer** receives raw data. The number of nodes it has depends on the data type: a 4x4 pixel image, for example, has 16 input nodes, one per pixel. The **hidden layers** in the middle process and refine that input, extracting increasingly complex features as the signal moves deeper. Each connection carries a **weight** that determines how much influence it has on the next layer. The **output layer** produces the final prediction.

![[Pasted image 20260708144815.png]]

Consider a neural network tasked with recognising a handwritten digit. Early hidden layers detect simple features like edges and curves. Deeper layers combine those features into more complex patterns. A straight vertical line increases the likelihood of a 1 or 7. Curves push probability toward 3, 8, or 0. The output layer has one node per possible digit, and whichever scores highest wins. When a network has more than three layers, it qualifies as a **Deep Learning (DL)** algorithm, hence the name.

The key distinction between and DL is that DL doesn't require labelled data. Where supervised needs a human to attach correct answers to training examples, a DL algorithm can take raw, unstructured input and determine its own features. No human intervention means larger datasets can be processed, which is why DL is sometimes described as scalable .

## LLMS

Large Language Models are deep learning-based models that process and generate text by predicting the next word in a sequence. When you send a message to a chatbot, what's happening in the background is a rapid series of predictions about what word should come next in the response, repeated until the reply is complete. The key question is: how does the model get good enough at those predictions to be useful?

LLMs are first trained in a **pre-training** phase, where they process enormous volumes of text. GPT-3 alone was trained on data that would take a human 2,600 years to read nonstop. Instead of labelled data, LLMs rely on billions of **parameters**, numerical values that function like puzzle pieces, collectively encoding the model's understanding of language. During pre-training, the model is fed a piece of text with the final word removed and asked to predict it. Its initial guess is random. That guess is then compared against the correct answer, and the parameters are adjusted via an algorithm called **backpropagation** to make the right answer more likely next time. Repeat this process trillions of times across a vast dataset and the model develops a remarkably accurate sense of how language works.

![LLM being fed sentence and making predictions on what last word will be](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1745606636896.svg)

The scale of pre-training is only possible because of advances in hardware (specifically GPUs enabling parallel processing) and a specific type of neural network called **transformer neural networks**. Introduced in Google's 2017 paper _Attention is All You Need_, transformers enabled parallel text processing instead of sequential word-by-word analysis. The key innovation was **attention**: the ability to assign different levels of importance to different words depending on context. Take this sentence:

_"The bank approved the loan because it was financially stable."_

A model without attention might struggle to resolve what "it" refers to. Transformers calculate attention scores across the whole sentence, correctly linking "it" back to "the bank" rather than "the loan."

After pre-training, humans come back into the loop in a process called **RLHF (Reinforcement Learning from Human Feedback)**. Reviewers evaluate model outputs, flag anything unhelpful or problematic, and the parameters are adjusted accordingly. This is the step that shapes a raw language model into something usable as a chatbot or assistant.

![[Pasted image 20260708151042.png]]