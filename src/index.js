import { VK, Keyboard, getRandomId } from 'vk-io'

import _ from 'lodash'

const vk = new VK({
  token: process.env.BOT_TOKEN
})

vk.updates.on('message_new', (context) => {
  if (context.text == 'Начать')
    return context.send({
      message: `Просто отправь картинки сюда, и бот их перекинет.`,
      keyboard: Keyboard.builder()
        .textButton({
          label: 'Начать',
          payload: {
            command: 'Начать'
          }
        })
    })

    processPhotos(context)
})

function findLargest(sizesArray) {
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

async function processPhotos(context) {
  async function sendPhotos() {
    const msgAttachments = (await vk.api.messages.getById({
      message_ids: context.id
    })).items[0].attachments
    if (context.hasAttachments("photo")) {
      let photoArray = []
      let promises = []
      msgAttachments.forEach((e) => {
        if (e.type == "photo") {
          promises.push(vk.upload.messagePhoto({
            peer_id: undefined,
            source: {
              value: findLargest(e.photo.sizes).url
            },
          })
          .then(attachment => {
            photoArray.push(attachment.toString())
          }))
        }
      })

      await Promise.all(promises)
      await vk.api.messages.send({
        peer_id: context.peerId,
        attachment: photoArray.join(","),
        random_id: getRandomId()
      })
    } else {
      context.send("❌ Я не вижу фотографий. Попробуй ещё раз.")
    }
  }
 
  await Promise.all([
    context.send('⌛ Жди...'),
    context.setActivity(),
    sendPhotos()
  ])
}

vk.updates.start().catch(console.error)