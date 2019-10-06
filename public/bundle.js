'use strict';

var vkIo = require('vk-io');

const vk = new vkIo.VK({
  token: "df46b437d524413be89c9db7368c53b2f169806e9e7fa81c039db0a945727ac06818d6ab8aae7cd5004bf"
});

vk.updates.hear('Начать', async (context) => {
  await context.send({
    message: `Чтобы бот перекинул вам картинки, отправьте сообщение с текстом "Перекинь" и прикрепленными картинками.`,
    keyboard: vkIo.Keyboard.keyboard([
      vkIo.Keyboard.textButton({
        label: 'Начать',
        payload: {
          command: 'Начать'
        }
      }),
    ])
  });
});

vk.updates.hear("Перекинь", async (context) => {
  function sendPhotos() {
    if (context.hasAttachments("photo")) {
      context.getAttachments("photo").forEach(element => {
        //photoArray.push(`photo${element.ownerId}_${element.id}_${element.accessKey}`)
        context.sendPhoto(element.largePhoto);
      });
    } else {
      context.send("Я не вижу фотографий. Попробуй ещё раз.");
    }
  }

  await Promise.all([
    context.send({
      message: 'Жди...'
    }),
    sendPhotos()
  ]);
});

/*vk.updates.hear("Перекинь", async (context) => {
  await Promise.all([
    context.send({
      message: 'Жди...',
      attachment: `photo${context.getAttachments()[0].ownerId}_${context.getAttachments()[0].id}`
    })
  ])
})*/

vk.updates.start().catch(console.error);
