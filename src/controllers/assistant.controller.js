const { OpenAI } = require("openai")
const databaseTools = require("../tools/database.tools")
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
const sessionService = require("../services/session.service")
exports.createThreadForSession = async (req, res) => {
  try {
    const { sessionId } = req.body
    const thread = await openai.beta.threads.create()
    await sessionService.addThreadIdToSession(sessionId, thread.id)
    res
      .status(201)
      .json({ threadId: thread.id, message: "Thread created successfully" })
  } catch (error) {
    console.error("Error creating thread:", error)
    res.status(500).json({ error: "Failed to create thread" })
  }
}

exports.getThreadById = async (req, res) => {
  const { threadId } = req.params
  try {
    const messages = await openai.beta.threads.messages.list(threadId)
    res.status(200).json({ threadId, messages: messages.data })
  } catch (error) {
    console.error("Error retrieving thread:", error)
    res.status(500).json({ error: "Failed to retrieve thread" })
  }
}

exports.addMessageToThread = async (req, res) => {
  const { threadId } = req.params
  const { message, userId, sessionId } = req.body
  console.log({ message, userId, sessionId, threadId })

  try {
    // Vérifier si un run est déjà actif
    let runs = await openai.beta.threads.runs.list(threadId)
    const activeRun = runs.data.find((r) =>
      ["in_progress", "queued", "requires_action"].includes(r.status)
    )
    if (activeRun) {
      // cancel the run
      openai.beta.threads.runs.cancel(threadId, activeRun.id)
    }
    // Ajouter le message utilisateur
    await openai.beta.threads.messages.create(threadId, {
      role: "user",
      content: `[context: userId=${userId}, sessionId=${sessionId}]\n\n${message}`,
      metadata: { userId, sessionId }
    })

    let run = await openai.beta.threads.runs.list(threadId)
    run = run.data.find((r) => ["in_progress", "queued"].includes(r.status))

    if (!run) {
      // Démarrer un run
      run = await openai.beta.threads.runs.create(threadId, {
        assistant_id: process.env.OPENAI_ASSISTANT_ID,
        max_prompt_tokens: 10000
      })
    }

    // Suivre le statut du run
    while (["queued", "in_progress", "requires_action"].includes(run.status)) {
      if (
        run.status === "requires_action" &&
        run.required_action?.submit_tool_outputs
      ) {
        const toolCalls = run.required_action.submit_tool_outputs.tool_calls
        const toolOutputs = []
        // Import database tools

        for (const toolCall of toolCalls) {
          const functionName = toolCall.function.name
          const args = JSON.parse(toolCall.function.arguments)

          // Override userId/sessionId with real values from the request
          if ('userId' in args) args.userId = userId
          if ('sessionId' in args) args.sessionId = sessionId

          console.log(`Executing tool: ${functionName} with args:`, args)

          let result
          if (databaseTools[functionName]) {
            // Always call with named arguments (object destructuring)
            result = await databaseTools[functionName](args)
          } else {
            result = { error: `Tool ${functionName} not found in toolHandlers` }
          }

          toolOutputs.push({
            tool_call_id: toolCall.id,
            output: JSON.stringify(result)
          })
        }

        // Soumettre les outputs au run
        await openai.beta.threads.runs.submitToolOutputs(threadId, run.id, {
          tool_outputs: toolOutputs
        })
      }

      // Attendre avant de re-check
      await new Promise((resolve) => setTimeout(resolve, 1000))

      // Récupérer le statut mis à jour
      run = await openai.beta.threads.runs.retrieve(threadId, run.id)
    }

    // Lire les messages de l’assistant
    const messages = await openai.beta.threads.messages.list(threadId)
    const assistantMessages = messages.data.filter(
      (m) => m.role === "assistant"
    )

    console.log({ messages, assistantMessages })
    const latestMessage = assistantMessages[0]?.content[0]?.text?.value
    if (!latestMessage) {
      throw new Error("No response from assistant")
    }
    let parsedMessage
    try {
      // Nettoyer la chaîne (enlever les espaces/retours à la ligne au début/fin)
      const cleaned = latestMessage.trim()
      parsedMessage = JSON.parse(cleaned)
    } catch (e) {
      // Si ce n'est pas du JSON, on garde le texte brut
      parsedMessage = latestMessage
    }
    res.status(200).json({ response: parsedMessage })
    return
  } catch (error) {
    console.error("Error adding message to thread:", error)
    res.status(500).json({ error: "Failed to process message" })
    return
  }
}
