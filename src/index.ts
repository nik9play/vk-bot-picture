import { VK, Keyboard, MessageContext, ContextDefaultState } from 'vk-io'
import _ from 'lodash'

const vk = new VK({
  token: process.env.BOT_TOKEN || ''
})

vk.updates.on('message_new', async (context) => {
  if (context.text == 'Начать')
    return context.send({
      message: `👇 Просто отправь картинки сюда, и бот их перекинет.`,
      keyboard: Keyboard.builder()
        .textButton({
          label: 'Начать',
          payload: {
            command: 'Начать'
          }
        })
    })

    try {
      await processPhotos(context)
    } catch (err) {
      console.error(err)
      context.send('❌ Произошла неизвестная ошибка.')
    }
})

async function processPhotos(context: MessageContext<ContextDefaultState>) { 
  const attachments = (await vk.api.messages.getById({
    message_ids: context.id
  })).items[0].attachments

  if (attachments && context.hasAttachments('photo')) {
    let photoArray = []

    photoArray = attachments
      .filter((attachment) => attachment.type === 'photo')
      .map((photo) => {
        const accessKey = photo.photo.access_key !== undefined
        ? `_${photo.photo.access_key}`
        : '';
  
        return `${photo.type}${photo.photo.owner_id}_${photo.photo.id}${accessKey}`;
      })

    await context.send({
      attachment: photoArray.join(',')
    })
  } else {
    await context.send("❌ Я не вижу фотографий. Попробуй ещё раз.")
  }
}

vk.updates.start().then(() => console.log('Bot started')).catch(console.error)