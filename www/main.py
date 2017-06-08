import asyncio
import m_orm
from models import User


async def main(loop):
    await m_orm.create_pool(loop=loop, user='root', password='930409', db='awesome', charset='UTF-8')
    # u = User(name='hwq', email='hwq@example.com', password='0987654321', image='about:blank')
    l = await User.findAll()
    print(l)
    await m_orm.destroy_pool()


loop = asyncio.get_event_loop()
loop.run_until_complete(main(loop))
loop.close()
