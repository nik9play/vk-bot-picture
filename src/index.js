import { VK, Keyboard } from 'vk-io'

const vk = new VK({
  token: process.env.BOT_TOKEN
})

vk.updates.hear('Начать', async (context) => {
  await context.send({
    message: `Чтобы бот перекинул вам картинки, отправьте сообщение с текстом "Перекинь" и прикрепленными картинками.`,
		// keyboard: Keyboard.builder()
		// 	.textButton({
		// 		label: 'Начать',
		// 		payload: {
		// 			command: 'Начать'
		// 		}
		// 	})
  })
})

vk.updates.hear(/п(е)?рек(и)?нь/i, async (context) => {
  context.setActivity()
  const sendPhotos = async () => {
    if (context.hasAttachments("photo")) {
      let photoArray = []
      for (const element of context.getAttachments("photo")) {
        await vk.upload.messagePhoto({
          source: element.largePhoto,
        })
        .then(attachment => {
          photoArray.push(attachment.toString())
        })
      }
      await vk.api.messages.send({
        peer_id: context.peerId,
        attachment: photoArray.join(",")
      })
    } else {
      context.send("Я не вижу фотографий. Попробуй ещё раз.")
    }
  }

  await Promise.all([
    context.send({
      message: 'Жди...'
    }),
    sendPhotos()
  ])
})

/*vk.updates.hear("Перекинь", async (context) => {
  await Promise.all([
    context.send({
      message: 'Жди...',
      attachment: `photo${context.getAttachments()[0].ownerId}_${context.getAttachments()[0].id}`
    })
  ])
})*/

vk.updates.start().catch(console.error)