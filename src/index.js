import { VK, Keyboard } from 'vk-io'
import _ from 'lodash'

const vk = new VK({
  token: process.env.BOT_TOKEN
})

vk.updates.hear('Начать', async (context) => {
  await context.send({
    message: `Чтобы бот перекинул вам картинки, отправьте сообщение с текстом "Перекинь" в любом виде и прикрепленными картинками. Отправьте "Начать" для дополнительной информации.`,
    keyboard: Keyboard.builder()
    	.textButton({
    		label: 'Начать',
    		payload: {
    			command: 'Начать'
    		}
    	})
  })
})

const findLargest = (sizesArray) => {
  const unwantedTypes = ["o", "p", "q", "r"]

  unwantedTypes.forEach(e => {
    _.remove(sizesArray, function(n) {
      return n.type == e;
    })
  })

  const newArray = _.sortBy(sizesArray, ["width"])
  _.reverse(newArray)

  return newArray[0]
}

vk.updates.hear(/п(е)?р(е)?к(и)?нь/i, async (context) => {
  const sendPhotos = async () => {
    await context.setActivity();
    if (context.hasAttachments("photo")) {
      let photoArray = []
      for (const element of context.getAttachments("photo")) {
        
        await vk.upload.messagePhoto({
          source: findLargest(element.sizes).url,
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

vk.updates.start().catch(console.error)